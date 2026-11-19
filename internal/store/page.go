// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"encoding/json"
	"sort"
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
	if issuer != s.m.Owner {
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
		p.collect(s.s, q, n.Children)
	case "kind":
		if !token(q.Kind) || q.ID != "" || q.Offset != 0 {
			return nil, ErrInvalid
		}
		p.collect(s.s, q, nil)
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

// Resident reference implementation; page limits bound output, not the scan.
// Ordered persistent indexes replace the sort without changing this ABI.
func (p *page) collect(s *state, q PageRequest, ids map[string]bool) {
	keys := []string{}
	if q.By == "children" {
		for id := range ids {
			if id > q.After {
				keys = append(keys, id)
			}
		}
	} else {
		for id, n := range s.nodes {
			if !n.Dead && n.Kind == q.Kind && id > q.After {
				keys = append(keys, id)
			}
		}
	}
	sort.Strings(keys)
	if len(keys) > q.Limit {
		keys = keys[:q.Limit]
		p.Next = keys[len(keys)-1]
	}
	for _, id := range keys {
		p.Items = append(p.Items, toItem(s.nodes[id]))
	}
}
