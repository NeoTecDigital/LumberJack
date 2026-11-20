// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"errors"
	"testing"

	"github.com/NeoTecDigital/LumberJack/extension"
)

type outcomeProbe struct {
	wants bool
	seen  []extension.Outcome
}

func (p *outcomeProbe) WantsRevision() bool        { return p.wants }
func (p *outcomeProbe) Settle(o extension.Outcome) { p.seen = append(p.seen, o) }
func TestRecordPermitFieldsMatchSettlement(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	for _, wants := range []bool{true, false} {
		p := &outcomeProbe{wants: wants}
		if _, e := s.Apply("operator", []byte("null"), p); e == nil {
			t.Fatal("accepted invalid command")
		}
		if len(p.seen) != 1 || p.seen[0].State != extension.WriteRefused || p.seen[0].Unchanged != wants || p.seen[0].Commit != (extension.Commit{}) {
			t.Fatal(p.seen)
		}
	}
	p := new(outcomeProbe)
	r, e := s.Apply("operator", []byte(create), p)
	if e != nil || len(p.seen) != 1 || p.seen[0].State != extension.WriteDurable || p.seen[0].Commit.Seq != r.Sequence || p.seen[0].Commit.Path != s.path || p.seen[0].Unchanged {
		t.Fatal(p.seen, e)
	}
	s.mu.Lock()
	s.fault = ErrUnavailable
	s.mu.Unlock()
	assertUnknown := func() {
		t.Helper()
		p := &outcomeProbe{wants: true}
		_, e := s.Apply("operator", []byte(create), p)
		if !errors.Is(e, ErrUnavailable) || len(p.seen) != 1 || p.seen[0].State != extension.WriteUnknown || p.seen[0].Unchanged || p.seen[0].Commit != (extension.Commit{}) {
			t.Fatal(p.seen, e)
		}
	}
	assertUnknown()
	s.mu.Lock()
	s.fault = nil
	s.mu.Unlock()
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	assertUnknown()
}
