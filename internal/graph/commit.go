// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import (
	"strconv"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// Commit validates one command against the graph under forest and only then writes it.
//
// Validation runs on a CANDIDATE built from a copy of the decoded state, so a command that is
// refused — for any reason — has touched nothing in the forest. The write phase that follows cannot
// fail. The caller holds the forest exclusively and persists after this returns; nothing here
// touches the disk.
func Commit(forest *core.Node, cmd Command, userID string, now time.Time) (Result, error) {
	if err := validateCommandShape(&cmd); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(cmd.Actor) == "" {
		cmd.Actor = userID
	}
	root := Root(forest)
	base, lay, err := load(root)
	if err != nil {
		return Result{}, err
	}
	receipt, found, err := lay.receipt(cmd.ID)
	if err != nil {
		return Result{}, err
	}
	if found {
		return replay(receipt, cmd)
	}
	st, err := stage(base, cmd)
	if err != nil {
		return Result{}, err
	}
	result := Result{CommandID: cmd.ID, Revision: st.candidate.Revision, Changes: st.changes, ResultMetadata: cmd.ResultMetadata}
	if root == nil {
		if root, err = ensureRoot(forest, userID); err != nil {
			return Result{}, err
		}
		lay.root = root
	}
	w := &writer{lay: lay, base: base, candidate: st.candidate, cmd: cmd, userID: userID, now: now}
	w.write(st, result)
	return result, nil
}

// replay answers a command whose id has been seen: the stored result if the payload is the same,
// a conflict if it is not.
func replay(receipt Receipt, cmd Command) (Result, error) {
	if receipt.Fingerprint != cmd.Fingerprint || receipt.ClientFingerprint != cmd.ClientFingerprint || receipt.PayloadDigest != commandDigest(cmd) {
		return Result{}, conflictf(commandsCollection, cmd.ID, "was already used with different content")
	}
	out := receipt.Result
	out.Replayed = true
	return out, nil
}

// staged is a validated candidate together with what producing it changed.
type staged struct {
	candidate *State
	changes   []Change
	scopes    map[string]struct{}
}

// stage builds and validates the candidate. It is the whole of what can refuse a command.
func stage(base *State, cmd Command) (staged, error) {
	if err := checkExpected(base, cmd.Expected); err != nil {
		return staged{}, err
	}
	if err := requireRecordExpected(base, cmd); err != nil {
		return staged{}, err
	}
	candidate := base.clone()
	changes, scopes, err := applyOperations(candidate, cmd)
	if err != nil {
		return staged{}, err
	}
	if err := validateImmutable(base, candidate, cmd); err != nil {
		return staged{}, err
	}
	if err := validateState(candidate); err != nil {
		return staged{}, err
	}
	if err := requireTopologyExpected(base, cmd.Expected, scopes); err != nil {
		return staged{}, err
	}
	candidate.Revision = base.Revision + 1
	bumpTopology(base, candidate, scopes)
	fillChangeRevisions(candidate, changes)
	return staged{candidate: candidate, changes: changes, scopes: scopes}, nil
}

// writer carries an accepted command into the forest nodes.
type writer struct {
	lay       *layout
	base      *State
	candidate *State
	cmd       Command
	userID    string
	now       time.Time
}

func (w *writer) write(st staged, result Result) {
	touched := map[string]struct{}{}
	for _, change := range st.changes {
		if change.Op == "put" {
			w.put(change.Collection, change.ID, touched)
		} else {
			w.remove(change.Collection, change.ID, touched)
		}
	}
	w.refreshScopes(st.scopes)
	w.relink(touched)
	w.storeReceipt(result)
	w.journal(result)
	root := w.lay.root
	root.Metadata = ensureMetadata(root.Metadata)
	root.Metadata[revisionKey] = strconv.FormatUint(w.candidate.Revision, 10)
	root.ModifiedBy, root.ModifiedAt = w.userID, w.now
}

// put writes the candidate's value onto the record's node, creating the node on first sight, and
// appends the history entry holding what it replaced.
func (w *writer) put(collection, id string, touched map[string]struct{}) {
	node := w.lay.node(collection, id)
	if node == nil {
		node = w.create(collection, id)
	}
	prior := w.storedText(w.base, collection, id)
	node.Metadata = ensureMetadata(node.Metadata)
	node.Metadata[recordKey] = w.storedText(w.candidate, collection, id)
	if collection == CollectionEntities {
		node.Kind = recordString(w.candidate.Entities[id], "kind")
	}
	node.ModifiedBy, node.ModifiedAt = w.userID, w.now
	node.AddEntry(
		map[string]interface{}{"type": kindPut, "command_id": w.cmd.ID, "actor": w.cmd.Actor, "prior": prior},
		map[string]interface{}{typedKey: kindPut}, w.userID, "", "")
	w.touch(collection, id, touched)
}

// storedText is a collection member as the text its node stores, or nil when the state lacks it.
func (w *writer) storedText(state *State, collection, id string) interface{} {
	if collection == CollectionAliases {
		target, ok := state.Aliases[id]
		if !ok {
			return nil
		}
		return recordText(target)
	}
	record := state.record(collection, id)
	if record == nil {
		return nil
	}
	return recordText(record)
}

func (w *writer) create(collection, id string) *core.Node {
	node := newGraphNode(nodeID(collection, id), id, w.userID, w.now)
	if collection == CollectionEntities {
		link(w.lay.root, node) // relink moves it under its scopes once every node exists
	} else {
		link(w.lay.ensureBucket(collection, w.userID, w.now), node)
	}
	w.lay.nodes[collection][id] = node
	return node
}

func (w *writer) remove(collection, id string, touched map[string]struct{}) {
	w.touch(collection, id, touched)
	node := w.lay.node(collection, id)
	if node == nil {
		return
	}
	for parentID := range node.Parents {
		if parent := w.parentNode(parentID); parent != nil {
			unlink(parent, node)
		}
	}
	node.Parents = map[string]string{}
	delete(w.lay.nodes[collection], id)
}

// touch marks the entities whose parentage a change may have moved: the entity itself, and the
// entity an occurrence placed before and after the change.
func (w *writer) touch(collection, id string, touched map[string]struct{}) {
	switch collection {
	case CollectionEntities:
		touched[id] = struct{}{}
	case CollectionOccurrences:
		for _, state := range []*State{w.base, w.candidate} {
			if entity := recordString(state.Occurrences[id], "entity_id"); entity != "" {
				touched[entity] = struct{}{}
			}
		}
	}
}

// refreshScopes writes the advanced topology_revision onto each scope whose membership changed.
// It is not a put, so no history entry is appended for it.
func (w *writer) refreshScopes(scopes map[string]struct{}) {
	for scopeID := range scopes {
		node := w.lay.node(CollectionEntities, scopeID)
		record := w.candidate.Entities[scopeID]
		if node == nil || record == nil {
			continue
		}
		node.Metadata[recordKey] = recordText(record)
	}
}

// relink makes each touched entity's parents exactly the scopes it has an occurrence in, or the
// graph root when it has none.
func (w *writer) relink(touched map[string]struct{}) {
	scopes := w.candidate.scopesOf()
	for id := range touched {
		node := w.lay.node(CollectionEntities, id)
		if node == nil || w.candidate.Entities[id] == nil {
			continue
		}
		w.syncParents(node, w.desiredParents(scopes[id]))
	}
}

func (w *writer) desiredParents(scopeIDs map[string]struct{}) map[string]*core.Node {
	desired := map[string]*core.Node{}
	for scopeID := range scopeIDs {
		if parent := w.lay.node(CollectionEntities, scopeID); parent != nil {
			desired[parent.ID] = parent
		}
	}
	if len(desired) == 0 {
		desired[w.lay.root.ID] = w.lay.root
	}
	return desired
}

func (w *writer) syncParents(node *core.Node, desired map[string]*core.Node) {
	for parentID := range node.Parents {
		if _, keep := desired[parentID]; keep {
			continue
		}
		if parent := w.parentNode(parentID); parent != nil {
			unlink(parent, node)
		} else {
			delete(node.Parents, parentID) // the parent left the graph in this same command
		}
	}
	for _, parent := range desired {
		if _, linked := node.Parents[parent.ID]; !linked {
			link(parent, node)
		}
	}
}

// parentNode resolves a parent id recorded on a graph node: the root, a bucket or an entity.
func (w *writer) parentNode(parentID string) *core.Node {
	if parentID == w.lay.root.ID {
		return w.lay.root
	}
	for _, bucket := range w.lay.buckets {
		if bucket != nil && bucket.ID == parentID {
			return bucket
		}
	}
	prefix := nodeID(CollectionEntities, "")
	if strings.HasPrefix(parentID, prefix) {
		return w.lay.node(CollectionEntities, strings.TrimPrefix(parentID, prefix))
	}
	return nil
}

// storeReceipt files the command's receipt under _commands. Receipts never expire: a retry a year
// later must still replay rather than reapply.
func (w *writer) storeReceipt(result Result) {
	receipt := Receipt{
		Fingerprint:       w.cmd.Fingerprint,
		ClientFingerprint: w.cmd.ClientFingerprint,
		PayloadDigest:     commandDigest(w.cmd),
		Actor:             w.cmd.Actor,
		At:                w.now.Format(time.RFC3339Nano),
		Result:            result,
	}
	node := newGraphNode(nodeID(commandsCollection, w.cmd.ID), w.cmd.ID, w.userID, w.now)
	node.Metadata[recordKey] = recordText(receipt)
	link(w.lay.ensureBucket(commandsCollection, w.userID, w.now), node)
	w.lay.nodes[commandsCollection][w.cmd.ID] = node
}

// journal appends the command's event to the graph root, which is what /graph/events reads. The
// revision is also on the entry's metadata so a page can be cut without decoding every event.
func (w *writer) journal(result Result) {
	event := Event{Revision: result.Revision, CommandID: w.cmd.ID, Actor: w.cmd.Actor, At: w.now.Format(time.RFC3339Nano), Changes: result.Changes}
	revision := strconv.FormatUint(event.Revision, 10)
	root := w.lay.root
	root.Entries = append(root.Entries, core.Entry{
		ID:        "graph:event:" + revision,
		Content:   map[string]interface{}{"type": kindCommand, "event": recordText(event)},
		Metadata:  map[string]interface{}{typedKey: kindCommand, "revision": revision},
		UserID:    w.userID,
		Timestamp: w.now,
	})
}
