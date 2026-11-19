// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/NeoTecDigital/LumberJack/core"
)

func (d *draft) edit(e framedEdit) error {
	if (e.Op == "append") != (e.Prefix != nil) {
		return ErrInvalid
	}
	if e.Op == "slot" {
		if len(e.Value) != 0 || !json.Valid(e.RawSlot) {
			return ErrInvalid
		}
		e.Value = json.RawMessage(e.RawSlot)
	} else if e.RawSlot != nil {
		return ErrInvalid
	}
	switch e.Op {
	case "create":
		return d.create(e)
	case "link", "unlink":
		return d.link(e.Parent, e.Child, e.Op == "link")
	case "delete":
		return d.remove(e.ID)
	case "field", "slot", "unset_field", "unset_slot", "append":
		return d.content(e)
	default:
		return ErrInvalid
	}
}
func isMinted(id string) bool {
	tail, ok := strings.CutPrefix(id, "node-")
	if !ok {
		return false
	}
	stamp, seq, ok := strings.Cut(tail, "-")
	if !ok {
		return false
	}
	for _, part := range []string{stamp, seq} {
		n, e := strconv.ParseUint(part, 10, 64)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != part {
			return false
		}
	}
	return true
}
func (d *draft) create(e framedEdit) error {
	if d.s.nodes[e.ID] != nil {
		return ErrConflict
	}
	if !token(e.Kind) || (!semanticID(e.ID) && !isMinted(e.ID)) {
		return ErrInvalid
	}
	n := newNode(e.ID, e.Kind)
	d.change(func() { d.s.nodes[e.ID] = n }, func() { delete(d.s.nodes, e.ID) })
	d.made[e.ID] = true
	d.touched[e.ID] = true
	d.created = append(d.created, e.ID)
	return nil
}
func (d *draft) content(e framedEdit) error {
	n, err := d.expect(e.ID, false)
	if err != nil {
		return err
	}
	if e.Op == "append" {
		if len(n.Entries) != *e.Prefix || !json.Valid(e.Value) {
			return ErrConflict
		}
		old := n.Entries
		d.change(func() { n.Entries = append(n.Entries, e.Value) }, func() { n.Entries = old })
		return nil
	}
	if !token(e.Key) {
		return ErrInvalid
	}
	target := &n.Fields
	if strings.HasSuffix(e.Op, "slot") {
		target = &n.Slots
	}
	if *target == nil {
		*target = values{}
	}
	m := *target
	old, ok := m[e.Key]
	unset := strings.HasPrefix(e.Op, "unset")
	if !unset && !json.Valid(e.Value) {
		return ErrInvalid
	}
	d.change(func() {
		if unset {
			delete(m, e.Key)
		} else {
			m[e.Key] = e.Value
		}
	}, func() {
		if ok {
			m[e.Key] = old
		} else {
			delete(m, e.Key)
		}
	})
	return nil
}
func (d *draft) link(parent, child string, add bool) error {
	p, err := d.expect(parent, true)
	if err != nil {
		return err
	}
	c, err := d.expect(child, true)
	if err != nil {
		return err
	}
	if child == Root || parent == child || p.Children[child] == add {
		return ErrConflict
	}
	if add && reaches(c, parent, d.s.nodes) {
		return ErrConflict
	}
	if p.Children == nil {
		p.Children = map[string]bool{}
	}
	if c.Parents == nil {
		c.Parents = map[string]bool{}
	}
	insert := func() { p.Children[child] = true; c.Parents[parent] = true }
	drop := func() { delete(p.Children, child); delete(c.Parents, parent) }
	if add {
		d.change(insert, drop)
	} else {
		d.change(drop, insert)
	}
	return nil
}
func reaches(start *node, id string, nodes map[string]*node) bool {
	if len(start.Children) == 0 {
		return false
	}
	todo := []*node{start}
	seen := map[string]bool{}
	for len(todo) > 0 {
		n := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if seen[n.ID] {
			continue
		}
		seen[n.ID] = true
		for child := range n.Children {
			if child == id {
				return true
			}
			todo = append(todo, nodes[child])
		}
	}
	return false
}
func (d *draft) remove(id string) error {
	if id == Root {
		return ErrConflict
	}
	n, err := d.expect(id, false)
	if err != nil {
		return err
	}
	if _, err = d.expect(id, true); err != nil {
		return err
	}
	for p := range n.Parents {
		if err := d.link(p, id, false); err != nil {
			return err
		}
	}
	for c := range n.Children {
		if err := d.link(id, c, false); err != nil {
			return err
		}
	}
	d.change(func() { n.Dead = true }, func() { n.Dead = false })
	return nil
}

// Resolve create aliases and stamp an explicit entry prefix, including zero, before staging.
func (s *state) frame(store, issuer, digest string, c Command) (*frame, error) {
	f := &frame{Version: 1, Sequence: s.sequence + 1, Store: store, Issuer: issuer, CommandID: c.ID, Digest: digest, Expected: c.Expected}
	aliases := map[string]string{}
	counts := map[string]int{}
	resolve := func(id string) string {
		if a := aliases[id]; a != "" {
			return a
		}
		return id
	}
	for i, e := range c.Edits {
		if e.Op == "create" {
			if e.ID == "" {
				e.ID = core.GenerateNodeID()
			}
			aliases["$"+strconv.Itoa(i)] = e.ID
		}
		e.ID = resolve(e.ID)
		e.Parent = resolve(e.Parent)
		e.Child = resolve(e.Child)
		op := framedEdit{Edit: e}
		if e.Op == "slot" {
			op.RawSlot = []byte(e.Value)
			op.Value = nil
		}
		if e.Op == "append" {
			v, ok := counts[e.ID]
			if !ok && s.nodes[e.ID] != nil {
				v = len(s.nodes[e.ID].Entries)
			}
			op.Prefix = &v
			counts[e.ID] = v + 1
		}
		f.Edits = append(f.Edits, op)
	}
	return f, nil
}
