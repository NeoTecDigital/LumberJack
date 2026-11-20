// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"encoding/json"
	"strings"
	"time"
)

type IndexPage struct {
	By       string          `json:"by,omitempty"`
	ID       string          `json:"id,omitempty"`
	Kind     string          `json:"kind,omitempty"`
	Index    string          `json:"index,omitempty"`
	From     json.RawMessage `json:"from,omitempty"`
	Until    json.RawMessage `json:"until,omitempty"`
	Equal    json.RawMessage `json:"equal,omitempty"`
	Cursor   string          `json:"cursor,omitempty"`
	Limit    int             `json:"limit,omitempty"`
	Offset   int             `json:"offset,omitempty"`
	Sequence *uint64         `json:"sequence,omitempty"`
}
type scanPlan struct{ prefix, lower, upper, kind, anchor string }
type indexResult struct {
	Sequence uint64 `json:"sequence"`
	Items    []item `json:"items"`
	Cursor   string `json:"cursor,omitempty"`
}

func (s *Store) keyPlan(q IndexPage) (scanPlan, error) {
	if q.ID != "" || q.Kind != "" || !token(q.Index) || q.Equal != nil && (q.From != nil || q.Until != nil) {
		return scanPlan{}, ErrInvalid
	}
	for _, x := range s.s.defs {
		if x.Name == q.Index {
			return rangePlan(q, x)
		}
	}
	return scanPlan{}, ErrInvalid
}
func rangePlan(q IndexPage, x Index) (scanPlan, error) {
	pre := bucket("f", x.Name, "")
	p := scanPlan{kind: x.Kind, prefix: pre, lower: pre}
	for _, b := range []struct {
		raw  json.RawMessage
		dest *string
	}{{q.From, &p.lower}, {q.Until, &p.upper}, {q.Equal, &p.prefix}} {
		if b.raw != nil {
			v, e := scalar(x.Type, b.raw)
			if e != nil {
				return p, e
			}
			*b.dest = pre + v + sep
		}
	}
	if q.Equal != nil {
		p.lower = p.prefix
	}
	if p.upper != "" && p.upper < p.lower {
		return p, ErrInvalid
	}
	return p, nil
}
func (s *Store) plan(q IndexPage, issuer string) (scanPlan, error) {
	if q.By == "key" {
		return s.keyPlan(q)
	}
	if q.From != nil || q.Until != nil || q.Equal != nil || q.Index != "" {
		return scanPlan{}, ErrInvalid
	}
	p := scanPlan{kind: q.Kind}
	switch q.By {
	case "kind":
		if !token(q.Kind) || q.ID != "" {
			return p, ErrInvalid
		}
		p.prefix = bucket("k", q.Kind, "")
	case "parents", "children", "incoming":
		if !token(q.ID) || q.Kind != "" && !token(q.Kind) {
			return p, ErrInvalid
		}
		if q.Kind == "" && issuer != s.m.Owner {
			return p, ErrDenied
		}
		axis := "p"
		if q.By == "children" {
			axis = "c"
		}
		p.anchor = q.ID
		p.prefix = bucket(axis, q.ID, q.Kind)
	default:
		return p, ErrInvalid
	}
	p.lower = p.prefix
	return p, nil
}
func (s *Store) authorizePage(issuer string, p scanPlan) error {
	if !s.visible(issuer, p.kind) {
		return ErrDenied
	}
	if p.anchor != "" {
		n := s.s.nodes[p.anchor]
		if n == nil || n.Dead || !s.visible(issuer, n.Kind) {
			return ErrAbsent
		}
	}
	return nil
}
func (s *Store) pageCursor(issuer string, q IndexPage) (cursor, error) {
	if q.Cursor != "" {
		if q.By != "" || q.Kind != "" || q.ID != "" || q.Index != "" || q.Equal != nil || q.From != nil || q.Until != nil {
			return cursor{}, ErrInvalid
		}
		c, e := s.leases.get(q.Cursor, issuer)
		if e != nil {
			return c, e
		}
		if c.access != s.s.access[issuer] {
			return cursor{}, ErrDenied
		}
		return c, s.authorizePage(issuer, c.plan)
	}
	p, e := s.plan(q, issuer)
	if e != nil {
		return cursor{}, e
	}
	c := cursor{root: s.s.index.root, seq: s.s.sequence, access: s.s.access[issuer], issuer: issuer, plan: p, expires: time.Now().Add(30 * time.Second)}
	return c, s.authorizePage(issuer, p)
}
func (s *Store) IndexedPage(issuer string, q IndexPage) ([]byte, error) {
	if q.By == "id" {
		if q.Cursor != "" || q.Index != "" || q.Kind != "" || q.From != nil || q.Until != nil || q.Equal != nil {
			return nil, ErrInvalid
		}
		return s.currentPage(issuer, PageRequest{By: "id", ID: q.ID, Limit: q.Limit, Offset: q.Offset, Sequence: q.Sequence}, true)
	}
	if q.Offset != 0 || q.Sequence != nil {
		return nil, ErrInvalid
	}
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return nil, ErrUnavailable
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > 256 {
		return nil, ErrInvalid
	}
	r, e := s.readIndex(issuer, q)
	if e != nil {
		return nil, e
	}
	return json.Marshal(r)
}
func (s *Store) readIndex(issuer string, q IndexPage) (indexResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out indexResult
	if s.fault != nil {
		return out, ErrUnavailable
	}
	if !s.canOpen(issuer, true) {
		return out, ErrDenied
	}
	c, e := s.pageCursor(issuer, q)
	if e != nil {
		return out, e
	}
	out.Sequence = c.seq
	out.Items = make([]item, 0, min(q.Limit, 50))
	more := false
	pos := c.plan.lower
	if c.last != "" {
		pos = c.last + sep
	}
	seek(c.root, pos, func(n *branch) bool {
		if !strings.HasPrefix(n.key, c.plan.prefix) || c.plan.upper != "" && n.key >= c.plan.upper {
			return false
		}
		if len(out.Items) == q.Limit {
			more = true
			return false
		}
		id := n.key[strings.LastIndexByte(n.key, 0)+1:]
		row := lookup(c.root, idkey(id))
		if row == nil || row.summary == nil {
			e = ErrUnavailable
			return false
		}
		out.Items = append(out.Items, *row.summary)
		c.last = n.key
		return true
	})
	if e != nil {
		return out, e
	}
	if more {
		if q.Cursor == "" {
			s.s.index.gen++
		}
		out.Cursor, e = s.leases.put(c)
	}
	return out, e
}
