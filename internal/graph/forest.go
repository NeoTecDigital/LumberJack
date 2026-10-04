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
// Node IDs are namespaced by collection. Entity and occurrence ids are both 64-hex and may collide
// across collections, and the state file keys its node table by id.
const (
	// RootName is the forest root's child the whole graph lives under.
	RootName = "graph"

	commandsCollection = "commands"
	recordKey          = "graph.record"
	revisionKey        = "graph.revision"
	typedKey           = "typed"
	kindCommand        = "graph.command"
	kindPut            = "graph.put"
	idPrefix           = "graph:"
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

// ensureRoot creates the graph root. AddChildNode copies the forest root's users onto it, which is
// what lets the same accounts reach the graph that reach the rest of the forest.
func ensureRoot(forest *core.Node, userID string) (*core.Node, error) {
	return forest.AddChildNode(RootName, core.BranchNode, userID)
}

// layout indexes the nodes a state was read from, so the write phase reaches each by id.
type layout struct {
	root    *core.Node
	buckets map[string]*core.Node
	nodes   map[string]map[string]*core.Node
}

func newLayout(root *core.Node) *layout {
	lay := &layout{root: root, buckets: map[string]*core.Node{}, nodes: map[string]map[string]*core.Node{}}
	lay.nodes[CollectionEntities] = map[string]*core.Node{}
	for _, collection := range bucketed {
		lay.nodes[collection] = map[string]*core.Node{}
	}
	return lay
}

func (lay *layout) node(collection, id string) *core.Node { return lay.nodes[collection][id] }

// load decodes the graph under root. A nil root is an empty graph at revision zero.
func load(root *core.Node) (*State, *layout, error) {
	state, lay := newState(), newLayout(root)
	if root == nil {
		return state, lay, nil
	}
	state.Revision = metaRevision(root.Metadata)
	if err := lay.loadEntities(state); err != nil {
		return nil, nil, err
	}
	for _, collection := range bucketed {
		if err := lay.loadBucket(state, collection); err != nil {
			return nil, nil, err
		}
	}
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

func (lay *layout) loadBucket(state *State, collection string) error {
	bucket := lay.root.Children[bucketID(collection)]
	lay.buckets[collection] = bucket
	if bucket == nil {
		return nil
	}
	prefix := nodeID(collection, "")
	for _, node := range bucket.Children {
		if node == nil || !strings.HasPrefix(node.ID, prefix) {
			continue
		}
		id := strings.TrimPrefix(node.ID, prefix)
		lay.nodes[collection][id] = node
		if err := loadMember(state, collection, id, node); err != nil {
			return err
		}
	}
	return nil
}

func loadMember(state *State, collection, id string, node *core.Node) error {
	switch collection {
	case commandsCollection:
		return nil // receipts are decoded on demand, by id
	case CollectionAliases:
		var target string
		if err := json.Unmarshal([]byte(metaText(node.Metadata, recordKey)), &target); err != nil {
			return fmt.Errorf("alias %q: %w", id, err)
		}
		state.Aliases[id] = target
		return nil
	}
	record, err := storedRecord(node)
	if err != nil {
		return err
	}
	state.put(collection, id, record)
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

// ensureBucket is the bucket a collection's nodes hang under, created on first use.
func (lay *layout) ensureBucket(collection, userID string, now time.Time) *core.Node {
	if bucket := lay.buckets[collection]; bucket != nil {
		return bucket
	}
	bucket := newGraphNode(bucketID(collection), bucketName(collection), userID, now)
	link(lay.root, bucket)
	lay.buckets[collection] = bucket
	return bucket
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
