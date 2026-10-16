// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import (
	"strconv"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// staged is a validated draft together with what producing it changed.
type staged struct {
	draft   *draft
	changes []Change
}

// stage builds and validates the draft. It is the whole of what can refuse a well-formed command.
func stage(base *State, ops []operation, expected Expected) (staged, error) {
	if err := checkExpected(base, expected); err != nil {
		return staged{}, err
	}
	if err := requireRecordExpected(expected, ops); err != nil {
		return staged{}, err
	}
	d := newDraft(base)
	changes, scopes := applyOperations(d, ops)
	if err := validateDraft(d); err != nil {
		return staged{}, err
	}
	if err := requireTopologyExpected(base, expected, scopes); err != nil {
		return staged{}, err
	}
	bumpTopology(d, scopes)
	fillChangeRevisions(d, changes)
	return staged{draft: d, changes: changes}, nil
}

// writer carries an accepted draft into the forest nodes, and then into the kept state. Every
// node it writes is reported to touched, before the write, so persistence can log the change.
type writer struct {
	lay     *layout
	state   *State
	draft   *draft
	cmd     Command
	digest  string
	userID  string
	now     time.Time
	touched *Touched
}

func (w *writer) write(result Result) {
	moved := w.moved()
	for _, k := range w.draft.order {
		if held := w.draft.slots[k]; held.live {
			w.put(k, held)
		} else {
			w.bury(k)
		}
	}
	for _, k := range w.draft.carried {
		node := w.lay.node(k.collection, k.id)
		w.touched.content(node)
		node.Metadata[recordKey] = w.draft.slots[k].text()
	}
	w.state.absorb(w.draft)
	w.relink(moved)
	w.storeReceipt(result)
	w.journal(result)
	root := w.lay.root
	w.touched.content(root)
	root.Metadata = ensureMetadata(root.Metadata)
	root.Metadata[revisionKey] = strconv.FormatUint(w.state.Revision, 10)
	root.ModifiedBy, root.ModifiedAt = w.userID, w.now
}

// put writes a member's value onto its node — creating the node on first sight, or taking its
// tombstone up again — and appends the history entry holding what it replaced. A re-creation
// replaces nothing live, so its prior is nil; the value it follows is on the delete entry before it.
func (w *writer) put(k key, held slot) {
	node, prior := w.lay.node(k.collection, k.id), interface{}(nil)
	switch {
	case node != nil:
		w.touched.content(node)
		prior = node.Metadata[recordKey]
	case w.lay.tombs[k] != nil:
		node = w.revive(k)
	default:
		node = w.create(k)
	}
	node.Metadata = ensureMetadata(node.Metadata)
	node.Metadata[recordKey] = held.text()
	if k.collection == CollectionEntities {
		node.Kind = recordString(held.record, "kind")
	}
	w.history(node, kindPut, prior)
}

func (w *writer) history(node *core.Node, kind string, prior interface{}) {
	w.touched.content(node)
	node.ModifiedBy, node.ModifiedAt = w.userID, w.now
	node.AddEntry(
		map[string]interface{}{"type": kind, "command_id": w.cmd.ID, "actor": w.cmd.Actor, "prior": prior},
		map[string]interface{}{typedKey: kind}, w.userID, "", "")
}

func (w *writer) create(k key) *core.Node {
	node := newGraphNode(nodeID(k.collection, k.id), k.id, w.userID, w.now)
	w.touched.created(node)
	if k.collection == CollectionEntities {
		w.link(w.lay.root, node) // relink moves it under its scopes once every node exists
	} else {
		w.link(w.bucket(k.collection), node)
	}
	w.lay.nodes[k.collection][k.id] = node
	return node
}

// revive takes a deleted record's node up again, history and all.
func (w *writer) revive(k key) *core.Node {
	node := w.lay.tombs[k]
	w.touched.content(node)
	delete(node.Metadata, tombstoneKey)
	if k.collection == CollectionEntities {
		w.unlink(w.lay.buckets[tombstonesCollection], node)
		w.link(w.lay.root, node)
	}
	delete(w.lay.tombs, k)
	w.lay.nodes[k.collection][k.id] = node
	return node
}

// bury turns a live record's node into its tombstone. The node is KEPT: it holds the record's
// history, and the tombstone on it is what a re-creation must continue from. A record that was
// not live — never created, or already deleted — is left exactly as it was.
func (w *writer) bury(k key) {
	node := w.lay.node(k.collection, k.id)
	tomb, live := w.state.entomb(k)
	if node == nil || !live {
		return
	}
	w.touched.content(node)
	prior := node.Metadata[recordKey]
	delete(node.Metadata, recordKey)
	node.Metadata[tombstoneKey] = recordText(tomb)
	w.history(node, kindDelete, prior)
	if k.collection == CollectionEntities {
		w.detach(node)
		w.link(w.bucket(tombstonesCollection), node)
	}
	delete(w.lay.nodes[k.collection], k.id)
	w.lay.tombs[k] = node
}

// detach takes an entity's node out of the containment tree, both ways. Nothing can still be
// placed in a deleted scope, so the children it lets go are relinked by this same command.
func (w *writer) detach(node *core.Node) {
	w.touched.edges(node)
	for parentID := range node.Parents {
		if parent := w.parentNode(parentID); parent != nil {
			w.touched.edges(parent)
			delete(parent.Children, node.ID)
		}
	}
	node.Parents = map[string]string{}
	for _, child := range node.Children {
		w.touched.edges(child)
		delete(child.Parents, node.ID)
	}
	node.Children = map[string]*core.Node{}
}

// link and unlink maintain both halves of an edge and report both ends touched.
func (w *writer) link(parent, child *core.Node) {
	w.touched.edges(parent)
	w.touched.edges(child)
	link(parent, child)
}

func (w *writer) unlink(parent, child *core.Node) {
	w.touched.edges(parent)
	w.touched.edges(child)
	unlink(parent, child)
}

// bucket is a collection's bucket, created on first use — and reported as created, with the root
// it hangs from.
func (w *writer) bucket(collection string) *core.Node {
	bucket, created := w.lay.ensureBucket(collection, w.userID, w.now)
	if created {
		w.touched.created(bucket)
		w.touched.edges(w.lay.root)
	}
	return bucket
}

// moved is the entities whose parentage the command may have changed: each entity it wrote, and
// the entity an occurrence placed before and after. It is read before the state is advanced.
func (w *writer) moved() map[string]struct{} {
	moved := map[string]struct{}{}
	for _, k := range w.draft.order {
		switch k.collection {
		case CollectionEntities:
			moved[k.id] = struct{}{}
		case CollectionOccurrences:
			moved[recordString(w.state.Occurrences[k.id], "entity_id")] = struct{}{}
			moved[recordString(w.draft.slots[k].record, "entity_id")] = struct{}{}
		}
	}
	delete(moved, "")
	return moved
}

// relink makes each moved entity's parents exactly the scopes it has an occurrence in, or the
// graph root when it has none. The state has been advanced, so its index is the new containment.
func (w *writer) relink(moved map[string]struct{}) {
	for id := range moved {
		node := w.lay.node(CollectionEntities, id)
		if node == nil {
			continue
		}
		w.syncParents(node, w.desiredParents(w.state.index.scopes[id]))
	}
}

func (w *writer) desiredParents(scopes map[string]string) map[string]*core.Node {
	desired := map[string]*core.Node{}
	for _, scopeID := range scopes {
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
			w.unlink(parent, node)
		} else {
			w.touched.edges(node)
			delete(node.Parents, parentID) // the parent left the graph in this same command
		}
	}
	for _, parent := range desired {
		if _, linked := node.Parents[parent.ID]; !linked {
			w.link(parent, node)
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
		Fingerprint:   w.cmd.Fingerprint,
		PayloadDigest: w.digest,
		Actor:         w.cmd.Actor,
		At:            w.now.Format(time.RFC3339Nano),
		Result:        result,
	}
	node := newGraphNode(nodeID(commandsCollection, w.cmd.ID), w.cmd.ID, w.userID, w.now)
	w.touched.created(node)
	node.Metadata[recordKey] = recordText(receipt)
	w.link(w.bucket(commandsCollection), node)
	w.lay.nodes[commandsCollection][w.cmd.ID] = node
}

// journal appends the command's event to the graph root, which is what /graph/events reads. The
// revision is also on the entry's metadata so a page can be cut without decoding every event.
func (w *writer) journal(result Result) {
	event := Event{Revision: result.Revision, CommandID: w.cmd.ID, Actor: w.cmd.Actor, At: w.now.Format(time.RFC3339Nano), Changes: result.Changes}
	revision := strconv.FormatUint(event.Revision, 10)
	root := w.lay.root
	w.touched.content(root)
	root.Entries = append(root.Entries, core.Entry{
		ID:        "graph:event:" + revision,
		Content:   map[string]interface{}{"type": kindCommand, "event": recordText(event)},
		Metadata:  map[string]interface{}{typedKey: kindCommand, "revision": revision},
		UserID:    w.userID,
		Timestamp: w.now,
	})
}
