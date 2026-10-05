// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// How the graph lies in the forest.
//
// The forest root has a child named `graph`. Every ENTITY is a node under it, and containment is
// parentage: an entity with an occurrence in a scope is a child of that scope's node, and one in no
// scope is a child of the graph root. Occurrences, edges, views, aliases and command receipts are
// nodes under the buckets `_occurrences`, `_edges`, `_views`, `_aliases` and `_commands`.
//
// A record is stored on its node as JSON TEXT under Metadata["graph.record"], not as a decoded map:
// metadata round-trips through encoding/json as float64, which writes 1000000 back as 1e+06 and
// would turn integer geometry into something the validator refuses. Text keeps every byte.
//
// A DELETED record keeps its node, and with it every history entry the node holds. The record text
// is replaced by a tombstone under Metadata["graph.tombstone"] — the last revision, the kind and
// the value. A bucketed record's tombstone stays in its bucket; a deleted entity is contained by
// nothing, so its node moves out of the containment tree to the `_tombstones` bucket.
//
// Node IDs are namespaced by collection. Entity and occurrence ids are both 64-hex and may collide
// across collections, and the state file keys its node table by id.
const (
	// RootName is the forest root's child the whole graph lives under.
	RootName = "graph"

	commandsCollection   = "commands"
	tombstonesCollection = "tombstones"
	recordKey            = "graph.record"
	tombstoneKey         = "graph.tombstone"
	revisionKey          = "graph.revision"
	typedKey             = "typed"
	kindCommand          = "graph.command"
	kindPut              = "graph.put"
	kindDelete           = "graph.delete"
	idPrefix             = "graph:"
)

// bucketed are the collections stored flat under a bucket rather than as the containment tree.
var bucketed = []string{CollectionOccurrences, CollectionEdges, CollectionViews, CollectionAliases, commandsCollection}

func nodeID(collection, id string) string { return idPrefix + collection + ":" + id }
func bucketID(collection string) string   { return idPrefix + "bucket:" + collection }
func bucketName(collection string) string {
	return "_" + collection
}

// Root is the graph root under a forest root, or nil before the first command creates it.
func Root(forest *core.Node) *core.Node {
	if forest == nil {
		return nil
	}
	return forest.ChildNamed(RootName)
}

// Owns reports whether node is the graph root or one of the nodes the engine keeps beneath it.
// Those are written by commands and by nothing else.
func Owns(forest, node *core.Node) bool {
	if node == nil {
		return false
	}
	return strings.HasPrefix(node.ID, idPrefix) || node == Root(forest)
}

// newRoot creates the graph root with access for the principal whose command created it, and for
// no one else. It does NOT inherit the forest root's users: an account that may write the forest
// has not thereby been given the graph, whose only writer is the one that checks identity and
// conformance before it sends a command.
func newRoot(forest *core.Node, userID string, now time.Time) *core.Node {
	root := core.NewNode(core.BranchNode, RootName)
	root.Metadata = map[string]interface{}{}
	root.CreatedBy, root.CreatedAt = userID, now
	root.ModifiedBy, root.ModifiedAt = userID, now
	root.Users = []core.User{creator(forest, userID)}
	link(forest, root)
	return root
}

// creator is the creating principal as the graph root lists it: identity and Admin, no credentials.
func creator(forest *core.Node, userID string) core.User {
	out := core.User{ID: userID, Permissions: []core.Permission{core.AdminPermission}}
	for _, user := range forest.Users {
		if user.ID == userID {
			out.Name, out.Username = user.Name, user.Username
		}
	}
	return out
}

// layout indexes the nodes a state was read from, so the write phase reaches each by id.
type layout struct {
	root    *core.Node
	buckets map[string]*core.Node
	nodes   map[string]map[string]*core.Node
	// tombs are the nodes of deleted records, which a re-creation takes up again.
	tombs map[key]*core.Node
}

func newLayout(root *core.Node) *layout {
	lay := &layout{root: root, buckets: map[string]*core.Node{}, nodes: map[string]map[string]*core.Node{}, tombs: map[key]*core.Node{}}
	lay.nodes[CollectionEntities] = map[string]*core.Node{}
	for _, collection := range bucketed {
		lay.nodes[collection] = map[string]*core.Node{}
	}
	return lay
}

func (lay *layout) node(collection, id string) *core.Node { return lay.nodes[collection][id] }

// load decodes the graph under root and indexes it. A nil root is an empty graph at revision zero.
func load(root *core.Node) (*State, *layout, error) {
	state, lay := newState(), newLayout(root)
	if root == nil {
		return state, lay, nil
	}
	state.Revision = metaRevision(root.Metadata)
	if err := lay.loadEntities(state); err != nil {
		return nil, nil, err
	}
	for _, collection := range append([]string{tombstonesCollection}, bucketed...) {
		if err := lay.loadBucket(state, collection); err != nil {
			return nil, nil, err
		}
	}
	state.reindex()
	return state, lay, nil
}

// loadEntities walks the entity nodes from the root down through their scopes. Containment is
// parentage, so every entity is reachable from the root through entity nodes alone.
func (lay *layout) loadEntities(state *State) error {
	prefix := nodeID(CollectionEntities, "")
	queue := entityChildren(lay.root, prefix)
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		id := strings.TrimPrefix(node.ID, prefix)
		if _, seen := lay.nodes[CollectionEntities][id]; seen {
			continue
		}
		record, err := storedRecord(node)
		if err != nil {
			return err
		}
		lay.nodes[CollectionEntities][id] = node
		state.Entities[id] = record
		queue = append(queue, entityChildren(node, prefix)...)
	}
	return nil
}

func entityChildren(node *core.Node, prefix string) []*core.Node {
	out := make([]*core.Node, 0, len(node.Children))
	for _, child := range node.Children {
		if child != nil && strings.HasPrefix(child.ID, prefix) {
			out = append(out, child)
		}
	}
	return out
}

// loadBucket reads one bucket's nodes. The `_tombstones` bucket holds deleted entities; every other
// bucket holds its own collection, live and deleted side by side.
func (lay *layout) loadBucket(state *State, collection string) error {
	bucket := lay.root.Children[bucketID(collection)]
	lay.buckets[collection] = bucket
	if bucket == nil {
		return nil
	}
	if collection == tombstonesCollection {
		collection = CollectionEntities
	}
	prefix := nodeID(collection, "")
	for _, node := range bucket.Children {
		if node == nil || !strings.HasPrefix(node.ID, prefix) {
			continue
		}
		if err := lay.loadMember(state, key{collection, strings.TrimPrefix(node.ID, prefix)}, node); err != nil {
			return err
		}
	}
	return nil
}

func (lay *layout) loadMember(state *State, k key, node *core.Node) error {
	if text := metaText(node.Metadata, tombstoneKey); text != "" {
		var tomb Tombstone
		if err := json.Unmarshal([]byte(text), &tomb); err != nil {
			return fmt.Errorf("node %q holds no graph tombstone: %w", node.ID, err)
		}
		lay.tombs[k], state.Tombstones[k] = node, tomb
		return nil
	}
	lay.nodes[k.collection][k.id] = node
	switch k.collection {
	case commandsCollection:
		return nil // receipts are decoded on demand, by id
	case CollectionAliases:
		var target string
		if err := json.Unmarshal([]byte(metaText(node.Metadata, recordKey)), &target); err != nil {
			return fmt.Errorf("alias %q: %w", k.id, err)
		}
		state.Aliases[k.id] = target
		return nil
	}
	record, err := storedRecord(node)
	if err != nil {
		return err
	}
	state.collection(k.collection)[k.id] = record
	return nil
}

func storedRecord(node *core.Node) (Record, error) {
	record, err := parseRecord(json.RawMessage(metaText(node.Metadata, recordKey)))
	if err != nil {
		return nil, fmt.Errorf("node %q holds no graph record: %w", node.ID, err)
	}
	return record, nil
}

// receipt is the stored receipt of a command, if the layout holds one.
func (lay *layout) receipt(id string) (Receipt, bool, error) {
	node := lay.node(commandsCollection, id)
	if node == nil {
		return Receipt{}, false, nil
	}
	return decodeReceipt(node)
}

func decodeReceipt(node *core.Node) (Receipt, bool, error) {
	var receipt Receipt
	if err := json.Unmarshal([]byte(metaText(node.Metadata, recordKey)), &receipt); err != nil {
		return Receipt{}, false, fmt.Errorf("receipt %q: %w", node.Name, err)
	}
	return receipt, true, nil
}

func metaText(metadata map[string]interface{}, key string) string {
	text, _ := metadata[key].(string)
	return text
}

func metaRevision(metadata map[string]interface{}) uint64 {
	value, _ := strconv.ParseUint(metaText(metadata, revisionKey), 10, 64)
	return value
}

func ensureMetadata(metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		return map[string]interface{}{}
	}
	return metadata
}

// ensureBucket is the bucket a collection's nodes hang under, created on first use — and whether
// this call created it.
func (lay *layout) ensureBucket(collection, userID string, now time.Time) (*core.Node, bool) {
	if bucket := lay.buckets[collection]; bucket != nil {
		return bucket, false
	}
	bucket := newGraphNode(bucketID(collection), bucketName(collection), userID, now)
	link(lay.root, bucket)
	lay.buckets[collection] = bucket
	return bucket, true
}

func newGraphNode(id, name, userID string, now time.Time) *core.Node {
	node := core.NewNode(core.BranchNode, name)
	node.ID = id
	node.Metadata = map[string]interface{}{}
	node.CreatedBy, node.CreatedAt = userID, now
	node.ModifiedBy, node.ModifiedAt = userID, now
	return node
}

// link and unlink maintain both halves of an edge: the parent's Children and the child's Parents.
// The caller holds the forest exclusively.
func link(parent, child *core.Node) {
	if parent.Children == nil {
		parent.Children = map[string]*core.Node{}
	}
	if child.Parents == nil {
		child.Parents = map[string]string{}
	}
	parent.Children[child.ID] = child
	child.Parents[parent.ID] = parent.Name
}

func unlink(parent, child *core.Node) {
	delete(parent.Children, child.ID)
	delete(child.Parents, parent.ID)
}
