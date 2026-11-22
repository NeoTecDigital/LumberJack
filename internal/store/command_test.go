// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.dat")
	s, e := Open(path, "operator")
	if e != nil {
		t.Fatal(e)
	}
	return s, path
}
func must(t *testing.T, s *Store, cmd string) Receipt {
	t.Helper()
	r, e := s.Apply("operator", []byte(cmd), nil)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

const create = `{"command_id":"first","edits":[{"op":"create","kind":"item"},{"op":"link","parent":"root","child":"$0"}],"expected":{"root":{"topology":0}}}`

func TestReceiptReplayAndDistinctIntent(t *testing.T) {
	s, p := openTest(t)
	r := must(t, s, create)
	r2 := must(t, s, create)
	if r.Sequence != r2.Sequence || r.Created[0] != r2.Created[0] {
		t.Fatal(r, r2)
	}
	if _, e := s.Apply("outsider", []byte(create), nil); !errors.Is(e, ErrDenied) {
		t.Fatal(e)
	}
	if _, e := s.Apply("operator", []byte(strings.Replace(create, "item", "other", 1)), nil); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e := Open(p, "operator")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if again := must(t, s, create); again.Sequence != r.Sequence {
		t.Fatal(again)
	}
	other := strings.Replace(strings.Replace(create, "first", "second", 1), `"topology":0`, `"topology":1`, 1)
	second := must(t, s, other)
	if r.Created[0] == second.Created[0] || second.Sequence != 2 {
		t.Fatal(second)
	}
}
func TestAtomicRefusalAndTombstone(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	id := strings.Repeat("a", 64)
	cmd := fmt.Sprintf(`{"command_id":"put","edits":[{"op":"create","id":"%s","kind":"item"},{"op":"link","parent":"root","child":"$0"}],"expected":{"root":{"topology":1}}}`, id)
	if _, e := s.Apply("operator", []byte(cmd), nil); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	if _, ok := s.s.nodes[id]; ok || s.s.sequence != 0 {
		t.Fatal("failed draft leaked")
	}
	late := strings.Replace(strings.Replace(cmd, `"topology":1`, `"topology":0`, 1), `"child":"$0"`, `"child":"missing"`, 1)
	if _, e := s.Apply("operator", []byte(late), nil); e == nil || s.s.nodes[id] != nil || s.s.sequence != 0 {
		t.Fatal("late draft edit leaked", e)
	}
	must(t, s, strings.Replace(cmd, `"topology":1`, `"topology":0`, 1))
	del := fmt.Sprintf(`{"command_id":"delete","expected":{"%s":{"revision":1,"topology":1},"root":{"topology":1}},"edits":[{"op":"delete","id":"%s"}]}`, id, id)
	must(t, s, del)
	if !s.s.nodes[id].Dead || len(s.s.nodes[Root].Children) != 0 {
		t.Fatal("delete did not unlink")
	}
	if _, e := s.Apply("operator", []byte(strings.Replace(cmd, `"put"`, `"recreate"`, 1)), nil); e == nil {
		t.Fatal("tombstone reused")
	}
}
func TestExplicitAppendBaseAndExactRawSlot(t *testing.T) {
	s, p := openTest(t)
	one := `{"command_id":"start","edits":[{"op":"slot","id":"root","key":"opaque","value":{"n" : 9007199254740993,"s":"<"}},{"op":"append","id":"root","value":1}],"expected":{"root":{"revision":0}}}`
	must(t, s, one)
	must(t, s, `{"command_id":"next","edits":[{"op":"append","id":"root","value":2}],"expected":{"root":{"revision":1}}}`)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e := Open(p, "operator")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	data, e := s.Page("operator", PageRequest{By: "id", ID: Root})
	if e != nil || !bytes.Contains(data, []byte("9007199254740993")) || !bytes.Contains(data, []byte(`"entries":[1,2]`)) {
		t.Fatalf("%s %v", data, e)
	}
	if string(s.s.nodes[Root].Slots["opaque"]) != `{"n" : 9007199254740993,"s":"<"}` {
		t.Fatal("raw slot changed on replay")
	}
	paths := s.log.Segments()
	raw, e := os.ReadFile(paths[0])
	if e != nil || !bytes.Contains(raw, []byte(`"entry_prefix":0`)) {
		t.Fatal("zero entry prefix was omitted", e)
	}
}
func TestSingleLinkDoesNotSerializeSevenHundredThousandSiblings(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	root := s.s.nodes[Root]
	root.Children = map[string]bool{}
	for i := 0; i < 700000; i++ {
		id := fmt.Sprintf("old-%d", i)
		s.s.nodes[id] = newNode(id, "leaf")
		root.Children[id] = true
	}
	must(t, s, create)
	raw, e := os.ReadFile(s.log.Segments()[0])
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("old-")) || bytes.Count(raw, []byte(`"op":"link"`)) != 1 || len(raw) > 2048 || len(root.Children) != 700001 {
		t.Fatalf("fanout log: %d bytes, %d children", len(raw), len(root.Children))
	}
}
func TestBadCreateIDAndBodyIssuerRefused(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	for _, cmd := range []string{strings.Replace(create, `"kind":"item"`, `"kind":"item","id":""`, 1), strings.Replace(create, `"kind":"item"`, `"kind":"item","id":null`, 1), strings.Replace(create, `"command_id"`, `"issuer":"someone","command_id"`, 1)} {
		if _, e := s.Apply("operator", []byte(cmd), nil); !errors.Is(e, ErrInvalid) {
			t.Fatal(e)
		}
	}
}
func TestPageContinuationPinsSequence(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	must(t, s, `{"command_id":"two","edits":[{"op":"create","kind":"x"},{"op":"create","kind":"x"}]}`)
	raw, e := s.Page("operator", PageRequest{By: "kind", Kind: "x", Limit: 1})
	var p page
	if e != nil || json.Unmarshal(raw, &p) != nil || len(p.Items) != 1 || p.Next == "" {
		t.Fatal(string(raw), e)
	}
	q := PageRequest{By: "kind", Kind: "x", Limit: 1, After: p.Next, Sequence: &p.Sequence}
	raw, e = s.Page("operator", q)
	if e != nil || bytes.Contains(raw, []byte(p.Next)) {
		t.Fatal(string(raw), e)
	}
	must(t, s, create)
	if _, e := s.Page("operator", q); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}

func TestIdenticalCreatesWithDifferentCommandIDs(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	const cmd = `{"command_id":"first","edits":[{"op":"create","kind":"item"}]}`
	a := must(t, s, cmd)
	b := must(t, s, strings.Replace(cmd, "first", "second", 1))
	if b.Sequence != a.Sequence+1 || a.Created[0] == b.Created[0] {
		t.Fatalf("%v %v", a, b)
	}
}
