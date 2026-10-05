// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import "github.com/NeoTecDigital/LumberJack/internal/core"

// What a command changed, node by node, so persistence can log the change and not the store.
//
// The engine is the only writer beneath the graph root, and its writes have a shape: a record's
// metadata is replaced, a history entry is APPENDED to its node, a journal entry is APPENDED to
// the root, and containment edges are made and unmade. Nothing it writes edits an existing entry
// or an untouched child list. That is what lets a touch say "the entries past this index are new
// and the children are as they were", and lets a record of a rename on a ten-thousand-entity
// graph carry one node and one journal entry rather than the root's whole child list.

// Touch is one node a command wrote.
type Touch struct {
	Node *core.Node
	// Content is anything but the edge maps: metadata, kind, stamps, entries.
	Content bool
	// Edges is the Children or Parents map. When false the stored children stand.
	Edges bool
	// EntriesBefore is how many entries the node held before the command first touched it; every
	// entry past that index was appended by the command. Zero for a node the command created.
	EntriesBefore int
}

// Touched collects the touches of one command, each node once, in the order first touched.
type Touched struct {
	order []*core.Node
	by    map[*core.Node]*Touch
}

// NewTouched is an empty set, for a tracked change that wrote nothing.
func NewTouched() *Touched {
	return &Touched{by: map[*core.Node]*Touch{}}
}

func newTouched() *Touched { return NewTouched() }

// touch is the node's touch, created on first sight with the entries it holds NOW — so it must be
// called before the command appends to the node.
func (t *Touched) touch(node *core.Node) *Touch {
	if held, seen := t.by[node]; seen {
		return held
	}
	held := &Touch{Node: node, EntriesBefore: len(node.Entries)}
	t.by[node] = held
	t.order = append(t.order, node)
	return held
}

// content marks a node's content changed.
func (t *Touched) content(node *core.Node) { t.touch(node).Content = true }

// edges marks a node's edge maps changed.
func (t *Touched) edges(node *core.Node) { t.touch(node).Edges = true }

// created marks a node the command brought into being: everything on it is new.
func (t *Touched) created(node *core.Node) {
	held := t.touch(node)
	held.Content, held.Edges, held.EntriesBefore = true, true, 0
}

// Rewrite marks a node changed in ways the engine did not make, so it is logged whole. It is for
// the caller that runs other writers after the command under the same hold.
func (t *Touched) Rewrite(node *core.Node) {
	held := t.touch(node)
	held.Content, held.Edges, held.EntriesBefore = true, true, 0
}

// List is every touch, in the order first touched.
func (t *Touched) List() []Touch {
	out := make([]Touch, 0, len(t.order))
	for _, node := range t.order {
		out = append(out, *t.by[node])
	}
	return out
}

// Len is how many nodes were touched.
func (t *Touched) Len() int { return len(t.order) }
