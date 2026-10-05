// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/internal/graph"
)

// What one hot-log record carries, and how it is built and applied.
//
// A record is the nodes a commit changed and the ids it deleted. Each node is encoded the way the
// state codec encodes a node — the node with its children named by id — with two additions that
// keep the record the size of the CHANGE when the node itself is large:
//
//   - entries_before: how many of the node's stored entries are kept; the entries in the record
//     are APPENDED after them. The graph root gains one journal entry per command and never loses
//     one, so a command logs that one entry rather than the whole journal. Zero means the record's
//     entries are the whole list, which is what a full node says.
//   - children_kept: the stored children stand; the record's list is to be ignored. A flat graph
//     root names every top-level entity, and a rename touches none of them.
//
// A node with neither set is the node whole, and replaces what was stored. Only the graph engine
// uses the partial forms, because only it can vouch that the stored entries and children were not
// touched. Everything else logs whole nodes.

// changeBody is one record's JSON.
type changeBody struct {
	Root    string                     `json:"root"`
	Nodes   map[string]json.RawMessage `json:"nodes"`
	Deleted []string                   `json:"deleted,omitempty"`
}

// logNode is a node as a record carries it. The outer Children and Entries SHADOW core.Node's own,
// by the same rule nodeRecord relies on, which is what lets one hold ids and the other a tail.
type logNode struct {
	*core.Node
	Children      []string     `json:"children"`
	Entries       []core.Entry `json:"entries"`
	ChildrenKept  bool         `json:"children_kept,omitempty"`
	EntriesBefore int          `json:"entries_before,omitempty"`
}

// encodeTouch encodes one node the graph engine reports.
func encodeTouch(touch graph.Touch) ([]byte, error) {
	node := touch.Node
	record := logNode{Node: node, ChildrenKept: !touch.Edges, EntriesBefore: touch.EntriesBefore}
	if touch.Edges {
		record.Children = childIDs(node)
	} else {
		record.Children = []string{}
	}
	if touch.EntriesBefore > len(node.Entries) {
		return nil, fmt.Errorf("node %q reports %d prior entries and holds %d", node.ID, touch.EntriesBefore, len(node.Entries))
	}
	record.Entries = node.Entries[touch.EntriesBefore:]
	if record.Entries == nil {
		record.Entries = []core.Entry{}
	}
	return json.Marshal(&record)
}

// encodeWholeNode encodes a node exactly as the state codec does.
func encodeWholeNode(node *core.Node, children []string) ([]byte, error) {
	return json.Marshal(&nodeRecord{Node: node, Children: children})
}

// trackedChange builds the record for nodes the graph engine reported, and invalidates their
// cache entries so the next whole-forest detection re-reads them.
func (t *tier) trackedChange(forest *core.Node, touched *graph.Touched) ([]byte, error) {
	touches := touched.List()
	if len(touches) == 0 {
		return nil, nil
	}
	body := changeBody{Root: forest.ID, Nodes: make(map[string]json.RawMessage, len(touches))}
	for _, touch := range touches {
		encoded, err := encodeTouch(touch)
		if err != nil {
			return nil, err
		}
		body.Nodes[touch.Node.ID] = encoded
		t.cache[touch.Node.ID] = nil
	}
	return json.Marshal(body)
}

// wholeForestChange finds what changed by encoding every node and comparing it with the bytes the
// cache holds from the last time it was seen. It costs the size of the forest, which is what a
// caller that cannot say what it changed pays; the graph engine never comes here.
func (t *tier) wholeForestChange(forest *core.Node) ([]byte, error) {
	body := changeBody{Root: forest.ID, Nodes: map[string]json.RawMessage{}}
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
		if held, known := t.cache[node.ID]; known && held != nil && string(held) == string(encoded) {
			return
		}
		t.cache[node.ID] = encoded
		body.Nodes[node.ID] = encoded
	})
	if failure != nil {
		return nil, failure
	}
	for id := range t.cache {
		if !visited[id] {
			body.Deleted = append(body.Deleted, id)
			delete(t.cache, id)
		}
	}
	if len(body.Nodes) == 0 && len(body.Deleted) == 0 {
		return nil, nil
	}
	sort.Strings(body.Deleted)
	return json.Marshal(body)
}

// applyChangeBody merges one record into a table during recovery.
func applyChangeBody(table *stateTable, seq uint64, data []byte) error {
	var body changeBody
	if err := json.Unmarshal(data, &body); err != nil {
		return fmt.Errorf("log record %d: %w", seq, err)
	}
	if body.Root != "" {
		table.Root = body.Root
	}
	for id, raw := range body.Nodes {
		if err := mergeLogNode(table, seq, id, raw); err != nil {
			return err
		}
	}
	for _, id := range body.Deleted {
		delete(table.records, id)
		delete(table.Nodes, id)
	}
	return nil
}

// mergeLogNode applies one node of a record over what the table holds.
func mergeLogNode(table *stateTable, seq uint64, id string, raw json.RawMessage) error {
	var incoming logNode
	if err := json.Unmarshal(raw, &incoming); err != nil || incoming.Node == nil {
		return fmt.Errorf("log record %d: node %q: %v", seq, id, err)
	}
	stored := table.records[id]
	merged := &nodeRecord{Node: incoming.Node, Children: incoming.Children}
	if incoming.ChildrenKept {
		if stored == nil {
			return fmt.Errorf("log record %d keeps the children of node %q, which the state file does not hold", seq, id)
		}
		merged.Children = stored.Children
	}
	merged.Node.Entries = incoming.Entries
	if incoming.EntriesBefore > 0 {
		if stored == nil || len(stored.Node.Entries) < incoming.EntriesBefore {
			return fmt.Errorf("log record %d keeps %d entries of node %q, which does not hold them", seq, incoming.EntriesBefore, id)
		}
		kept := stored.Node.Entries[:incoming.EntriesBefore:incoming.EntriesBefore]
		merged.Node.Entries = append(kept, incoming.Entries...)
	}
	table.records[id] = merged
	// The raw bytes no longer describe the node; the cache re-encodes it at open.
	delete(table.Nodes, id)
	return nil
}
