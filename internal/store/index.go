// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

type Index struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Field string `json:"field"`
	Type  string `json:"type"`
}

const sep = "\x00"

func normalized(in []Index) ([]Index, error) {
	if len(in) > 16 {
		return nil, ErrInvalid
	}
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b Index) int { return strings.Compare(a.Name, b.Name) })
	for i, x := range out {
		if !token(x.Name) || !token(x.Kind) || !token(x.Field) || len(x.Name) > 48 || len(x.Kind) > 64 || len(x.Field) > 64 || i > 0 && out[i-1].Name == x.Name {
			return nil, ErrInvalid
		}
		if x.Type != "string" && x.Type != "int64" && x.Type != "bool" {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func scalar(typ string, raw json.RawMessage) (string, error) {
	if bytes.Equal(raw, []byte("null")) || len(raw) == 0 {
		return "", ErrInvalid
	}
	switch typ {
	case "string":
		var s string
		if json.Unmarshal(raw, &s) != nil || len(s) > 1024 {
			return "", ErrInvalid
		}
		return hex.EncodeToString([]byte(s)), nil
	case "int64":
		var n int64
		if json.Unmarshal(raw, &n) != nil {
			return "", ErrInvalid
		}
		v := strconv.FormatUint(uint64(n)^(uint64(1)<<63), 16)
		return strings.Repeat("0", 16-len(v)) + v, nil
	case "bool":
		var b bool
		if json.Unmarshal(raw, &b) != nil {
			return "", ErrInvalid
		}
		if b {
			return "1", nil
		}
		return "0", nil
	}
	return "", ErrInvalid
}
func idkey(id string) string                { return "i" + sep + id }
func bucket(axis, term, kind string) string { return axis + sep + term + sep + kind + sep }
func kindkey(kind, id string) string        { return bucket("k", kind, "") + id }
func (d *draft) posting(key string, add bool) {
	t := &d.s.index
	put := func() { t.set(key, nil) }
	drop := func() { t.drop(key) }
	if add {
		d.change(put, drop)
	} else {
		d.change(drop, put)
	}
}
func (d *draft) fieldPost(n *node, field string, raw json.RawMessage, add bool) error {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	for _, x := range d.s.defs {
		if x.Kind != n.Kind || x.Field != field {
			continue
		}
		if err := d.scalarPost(x, n.ID, raw, add); err != nil {
			return err
		}
	}
	return nil
}
func (d *draft) edgePosts(axis string, from, to *node, add bool) {
	d.posting(bucket(axis, from.ID, "")+to.ID, add)
	d.posting(bucket(axis, from.ID, to.Kind)+to.ID, add)
}
func (d *draft) summarize(n *node) {
	key := idkey(n.ID)
	old := lookup(d.s.index.root, key)
	var prev *item
	if old != nil {
		prev = old.summary
	}
	v := toItem(n)
	next := &v
	if n.Dead {
		next = nil
	}
	set := func(it *item) {
		if it == nil {
			d.s.index.drop(key)
		} else {
			d.s.index.set(key, it)
		}
	}
	d.change(func() { set(next) }, func() { set(prev) })
}

func (d *draft) scalarPost(x Index, id string, raw json.RawMessage, add bool) error {
	v, e := scalar(x.Type, raw)
	if e != nil {
		return e
	}
	d.posting(bucket("f", x.Name, "")+v+sep+id, add)
	return nil
}
func (d *draft) unindexNode(n *node) error {
	for _, x := range d.s.defs {
		raw := n.Fields[x.Field]
		if x.Kind != n.Kind || len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
			continue
		}
		if err := d.scalarPost(x, n.ID, raw, false); err != nil {
			return err
		}
	}
	return nil
}
