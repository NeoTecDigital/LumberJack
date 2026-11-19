// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import "encoding/json"

type values = map[string]json.RawMessage
type node struct {
	ID, Kind           string
	Revision, Topology uint64
	Fields, Slots      values
	Entries            []json.RawMessage
	Children, Parents  map[string]bool
	Dead               bool
}

func newNode(id, kind string) *node { return &node{ID: id, Kind: kind} }

type receiptKey struct{ issuer, id string }
type saved struct {
	result Receipt
	digest string
}
type state struct {
	nodes    map[string]*node
	receipts map[receiptKey]saved
	sequence uint64
}

func empty() *state {
	return &state{nodes: map[string]*node{Root: newNode(Root, "root")}, receipts: map[receiptKey]saved{}}
}

type change struct{ apply, undo func() }
type changes []change

func (c changes) reverse() {
	for i := len(c) - 1; i >= 0; i-- {
		c[i].undo()
	}
}
func (c changes) publish() {
	for _, x := range c {
		x.apply()
	}
}

type draft struct {
	s              *state
	f              *frame
	changes        changes
	made           map[string]bool
	touched, links map[string]bool
	created        []string
}

func (d *draft) change(do, undo func()) { do(); d.changes = append(d.changes, change{do, undo}) }
func (d *draft) expect(id string, top bool) (*node, error) {
	n := d.s.nodes[id]
	if n == nil || n.Dead {
		return nil, ErrAbsent
	}
	if !d.made[id] {
		e := d.f.Expected[id]
		if top && e.Topology == nil || !top && e.Revision == nil {
			return nil, ErrConflict
		}
	}
	if top {
		d.links[id] = true
	} else {
		d.touched[id] = true
	}
	return n, nil
}
func checkExpected(s *state, expected map[string]Expected) error {
	for id, w := range expected {
		if !token(id) || w.Revision == nil && w.Topology == nil {
			return ErrInvalid
		}
		var r, t uint64
		if n := s.nodes[id]; n != nil {
			r, t = n.Revision, n.Topology
		}
		if w.Revision != nil && r != *w.Revision || w.Topology != nil && t != *w.Topology {
			return ErrConflict
		}
	}
	return nil
}
func (d *draft) finish() {
	for id := range d.touched {
		n := d.s.nodes[id]
		d.change(func() { n.Revision++ }, func() { n.Revision-- })
	}
	for id := range d.links {
		n := d.s.nodes[id]
		d.change(func() { n.Topology++ }, func() { n.Topology-- })
	}
}
func (s *state) run(f *frame) (changes, Receipt, error) {
	var out Receipt
	if f.Version != 1 || f.Sequence != s.sequence+1 || !semanticID(f.Digest) || !token(f.Issuer) || !token(f.CommandID) || len(f.Edits) < 1 || len(f.Edits) > MaxEdits {
		return nil, out, ErrInvalid
	}
	key := receiptKey{f.Issuer, f.CommandID}
	if _, ok := s.receipts[key]; ok {
		return nil, out, ErrConflict
	}
	if err := checkExpected(s, f.Expected); err != nil {
		return nil, out, err
	}
	d := draft{s: s, f: f, made: map[string]bool{}, touched: map[string]bool{}, links: map[string]bool{}}
	for _, e := range f.Edits {
		if err := d.edit(e); err != nil {
			d.changes.reverse()
			return nil, out, err
		}
	}
	d.finish()
	out = Receipt{f.CommandID, f.Sequence, d.created}
	d.change(func() { s.sequence++; s.receipts[key] = saved{out, f.Digest} }, func() { s.sequence--; delete(s.receipts, key) })
	return d.changes, out, nil
}
