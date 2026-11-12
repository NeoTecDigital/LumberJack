// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// The change set: what one hot-log record carries, how a commit's is found, and how recovery
// applies it.
//
// A change set is the nodes a commit changed and the ids it deleted. Each node is the node WHOLE,
// encoded exactly as the state codec encodes it — the node with its children named by id — so
// recovery replaces what the state file held with it, and a record is the size of the change
// rather than the size of the store.
//
// IT IS FOUND, NOT REPORTED. After every commit the forest is encoded node by node and compared
// with the bytes the tier's cache holds from the last time each node was seen: a node that is new
// or whose bytes differ is in the set, and one the walk no longer reaches is deleted. That is
// correct for every writer whatever it changed, because no writer is trusted to say what it
// changed. It costs one encode of the forest under the hold; the disk is written only the change.
//
// A build that carried pdl's graph engine also logged PARTIAL nodes: `entries_before` (the
// record's entries are appended past that many stored ones) and `children_kept` (the stored
// children stand). Nothing in this build writes them, and applying one as a whole node would drop
// the entries and children it left out, so recovery refuses a log holding one rather than reading
// it wrongly. Such a store is folded into its state file by a clean shutdown of the build that
// wrote it.

// changeSet is one record's JSON.
type changeSet struct {
	Root    string                     `json:"root"`
	Nodes   map[string]json.RawMessage `json:"nodes"`
	Deleted []string                   `json:"deleted,omitempty"`
}

// logNode is a node as recovery reads it from a record: the state codec's node record, whose
// Children SHADOW core.Node's own by the rule nodeRecord relies on, and the two partial-form
// markers it refuses.
type logNode struct {
	*core.Node
	Children      []string `json:"children"`
	ChildrenKept  bool     `json:"children_kept,omitempty"`
	EntriesBefore int      `json:"entries_before,omitempty"`
}

// encodeWholeNode encodes a node exactly as the state codec does.
func encodeWholeNode(node *core.Node, children []string) ([]byte, error) {
	return json.Marshal(&nodeRecord{Node: node, Children: children})
}

// detectChangeSet finds what changed since the last commit by encoding every node and comparing
// it with the bytes the cache holds, and answers the record for it, or nil when nothing changed.
// The caller holds the forest exclusively.
func (t *tier) detectChangeSet(forest *core.Node) ([]byte, error) {
	set := changeSet{Root: forest.ID, Nodes: map[string]json.RawMessage{}}
	visited := make(map[string]bool, len(t.cache))
	var failure error
	walkForest(forest, func(node *core.Node, children []string) {
		if failure != nil {
			return
		}
		visited[node.ID] = true
		encoded, err := encodeWholeNode(node, children)
		if err != nil {
			failure = err
			return
		}
		if held, known := t.cache[node.ID]; known && string(held) == string(encoded) {
			return
		}
		t.cache[node.ID] = encoded
		set.Nodes[node.ID] = encoded
	})
	if failure != nil {
		return nil, failure
	}
	for id := range t.cache {
		if !visited[id] {
			set.Deleted = append(set.Deleted, id)
			delete(t.cache, id)
		}
	}
	if len(set.Nodes) == 0 && len(set.Deleted) == 0 {
		return nil, nil
	}
	sort.Strings(set.Deleted)
	return json.Marshal(set)
}

// applyChangeSet merges one record into a table during recovery.
func applyChangeSet(table *stateTable, seq uint64, data []byte) error {
	var set changeSet
	if err := json.Unmarshal(data, &set); err != nil {
		return fmt.Errorf("log record %d: %w", seq, err)
	}
	if set.Root != "" {
		table.Root = set.Root
	}
	for id, raw := range set.Nodes {
		if err := mergeLogNode(table, seq, id, raw); err != nil {
			return err
		}
	}
	for _, id := range set.Deleted {
		delete(table.records, id)
		delete(table.Nodes, id)
	}
	return nil
}

// mergeLogNode replaces what the table holds for one node with the node a record carries.
func mergeLogNode(table *stateTable, seq uint64, id string, raw json.RawMessage) error {
	var incoming logNode
	if err := decodeExact(raw, &incoming); err != nil || incoming.Node == nil {
		return fmt.Errorf("log record %d: node %q: %v", seq, id, err)
	}
	if incoming.ChildrenKept || incoming.EntriesBefore != 0 {
		return fmt.Errorf("log record %d: node %q is a partial node (children_kept or entries_before), which this "+
			"build does not apply; shut the store down cleanly with the build that wrote it to fold the log into "+
			"the state file", seq, id)
	}
	table.records[id] = &nodeRecord{Node: incoming.Node, Children: incoming.Children}
	// The raw bytes no longer describe the node; the cache re-encodes it at open.
	delete(table.Nodes, id)
	return nil
}
