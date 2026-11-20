// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"encoding/json"
	"strings"
)

type PageRequest struct {
	By       string  `json:"by"`
	ID       string  `json:"id,omitempty"`
	Kind     string  `json:"kind,omitempty"`
	Limit    int     `json:"limit,omitempty"`
	After    string  `json:"after,omitempty"`
	Sequence *uint64 `json:"sequence,omitempty"`
	Offset   int     `json:"offset,omitempty"`
}
type item struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Revision uint64 `json:"revision"`
	Topology uint64 `json:"topology"`
}
type page struct {
	Sequence   uint64            `json:"sequence"`
	Items      []item            `json:"items"`
	Next       string            `json:"next,omitempty"`
	Fields     values            `json:"fields,omitempty"`
	Slots      values            `json:"slots,omitempty"`
	Entries    []json.RawMessage `json:"entries,omitempty"`
	NextOffset int               `json:"next_offset,omitempty"`
}

func (s *Store) Page(issuer string, q PageRequest) ([]byte, error) {
	return s.currentPage(issuer, q, false)
}
func (s *Store) currentPage(issuer string, q PageRequest, scopedID bool) ([]byte, error) {
	if issuer != s.m.Owner && !scopedID {
		return nil, ErrDenied
	}
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return nil, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.fault != nil {
		return nil, ErrUnavailable
	}
	if scopedID {
		n := s.s.nodes[q.ID]
		if !s.canOpen(issuer, true) {
			return nil, ErrDenied
		}
		if n == nil || n.Dead || !s.visible(issuer, n.Kind) {
			return nil, ErrAbsent
		}
	}
	return s.renderPage(q)
}

// renderPage runs under the committed-state read lock.
func (s *Store) renderPage(q PageRequest) ([]byte, error) {
	if q.Sequence != nil && *q.Sequence != s.s.sequence {
		return nil, ErrConflict
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > 256 || q.Offset < 0 {
		return nil, ErrInvalid
	}
	if (q.After != "" || q.Offset != 0) && q.Sequence == nil {
		return nil, ErrInvalid
	}
	p := page{Sequence: s.s.sequence, Items: []item{}}
	switch q.By {
	case "id", "children":
		if !token(q.ID) || q.Kind != "" {
			return nil, ErrInvalid
		}
		n := s.s.nodes[q.ID]
		if n == nil || n.Dead {
			return nil, ErrAbsent
		}
		if q.By == "id" {
			if q.After != "" || q.Offset > len(n.Entries) {
				return nil, ErrInvalid
			}
			p.detail(n, q)
			break
		}
		if q.Offset != 0 {
			return nil, ErrInvalid
		}
		p.collect(s.s, q, bucket("c", q.ID, ""))
	case "kind":
		if !token(q.Kind) || q.ID != "" || q.Offset != 0 {
			return nil, ErrInvalid
		}
		p.collect(s.s, q, bucket("k", q.Kind, ""))
	default:
		return nil, ErrInvalid
	}
	return json.Marshal(p)
}
func toItem(n *node) item { return item{n.ID, n.Kind, n.Revision, n.Topology} }
func (p *page) detail(n *node, q PageRequest) {
	p.Items = []item{toItem(n)}
	p.Fields = n.Fields
	p.Slots = n.Slots
	end := q.Offset + min(q.Limit, len(n.Entries)-q.Offset)
	p.Entries = n.Entries[q.Offset:end]
	if end < len(n.Entries) {
		p.NextOffset = end
	}
}

// Legacy cursor semantics (restart on commit), using the same ordered postings.
func (p *page) collect(s *state, q PageRequest, pre string) {
	lo := pre
	if q.After != "" {
		lo += q.After + sep
	}
	seek(s.index.root, lo, func(n *branch) bool {
		if !strings.HasPrefix(n.key, pre) {
			return false
		}
		if len(p.Items) == q.Limit {
			p.Next = p.Items[len(p.Items)-1].ID
			return false
		}
		p.Items = append(p.Items, toItem(s.nodes[n.key[len(pre):]]))
		return true
	})
}
