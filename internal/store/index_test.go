// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func indexRead(t *testing.T, s *Store, issuer string, q IndexPage) indexResult {
	t.Helper()
	raw, e := s.IndexedPage(issuer, q)
	if e != nil {
		t.Fatal(e)
	}
	var r indexResult
	if e = json.Unmarshal(raw, &r); e != nil {
		t.Fatal(e)
	}
	return r
}
func rowIDs(r indexResult) []string {
	ids := make([]string, len(r.Items))
	for i, n := range r.Items {
		ids[i] = n.ID
	}
	return ids
}
func wantIDs(t *testing.T, r indexResult, want ...string) {
	t.Helper()
	if !slices.Equal(rowIDs(r), want) {
		t.Fatal("rows", rowIDs(r), "want", want)
	}
}
func TestIndexedDiamondAndOnePlacementRemoval(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	r := must(t, s, `{"command_id":"diamond","expected":{"root":{"topology":0}},"edits":[{"op":"create","kind":"group"},{"op":"create","kind":"group"},{"op":"create","kind":"leaf"},{"op":"link","parent":"root","child":"$0"},{"op":"link","parent":"root","child":"$1"},{"op":"link","parent":"$0","child":"$2"},{"op":"link","parent":"$1","child":"$2"}]}`)
	a, b, c := r.Created[0], r.Created[1], r.Created[2]
	want := []string{a, b}
	slices.Sort(want)
	wantIDs(t, indexRead(t, s, "operator", IndexPage{By: "incoming", ID: c}), want...)
	for _, p := range want {
		wantIDs(t, indexRead(t, s, "operator", IndexPage{By: "children", ID: p}), c)
	}
	wantIDs(t, indexRead(t, s, "operator", IndexPage{By: "kind", Kind: "leaf"}), c)
	must(t, s, fmt.Sprintf(`{"command_id":"detach","expected":{"%s":{"topology":1},"%s":{"topology":1}},"edits":[{"op":"unlink","parent":"%s","child":"%s"}]}`, a, c, a, c))
	wantIDs(t, indexRead(t, s, "operator", IndexPage{By: "parents", ID: c}), b)
	wantIDs(t, indexRead(t, s, "operator", IndexPage{By: "children", ID: a}))
	wantIDs(t, indexRead(t, s, "operator", IndexPage{By: "children", ID: b}), c)
}
func TestDeclaredIndexRangeUpdatesRollbackAndReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	defs := []Index{{"score", "row", "rank", "int64"}}
	s, e := OpenIndexed(path, "operator", defs, false)
	if e != nil {
		t.Fatal(e)
	}
	r := must(t, s, `{"command_id":"rows","edits":[{"op":"create","kind":"row"},{"op":"field","id":"$0","key":"rank","value":-5},{"op":"create","kind":"row"},{"op":"field","id":"$2","key":"rank","value":9007199254740993},{"op":"create","kind":"row"},{"op":"field","id":"$4","key":"rank","value":9007199254740992}]}`)
	a, b, c := r.Created[0], r.Created[1], r.Created[2]
	q := IndexPage{By: "key", Index: "score", From: json.RawMessage(`-5`), Until: json.RawMessage(`9007199254740993`)}
	wantIDs(t, indexRead(t, s, "operator", q), a, c)
	bad := fmt.Sprintf(`{"command_id":"bad","expected":{"%s":{"revision":1}},"edits":[{"op":"field","id":"%s","key":"rank","value":42},{"op":"field","id":"%s","key":"rank","value":"wrong"}]}`, a, a, a)
	if _, e = s.Apply("operator", []byte(bad), nil); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	wantIDs(t, indexRead(t, s, "operator", q), a, c)
	must(t, s, fmt.Sprintf(`{"command_id":"update","expected":{"%s":{"revision":1},"%s":{"revision":1}},"edits":[{"op":"unset_field","id":"%s","key":"rank"},{"op":"field","id":"%s","key":"rank","value":-6}]}`, a, b, a, b))
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenIndexed(path, "operator", nil, false); !errors.Is(e, ErrConflict) {
		t.Fatal("changed declaration", e)
	}
	s, e = OpenIndexed(path, "operator", defs, false)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	wantIDs(t, indexRead(t, s, "operator", q), c)
	wantIDs(t, indexRead(t, s, "operator", IndexPage{By: "key", Index: "score", Equal: json.RawMessage(`-6`)}), b)
}
func TestIndexedCursorRetainsSnapshotAcrossCommit(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	must(t, s, fmt.Sprintf(`{"command_id":"rows","edits":[{"op":"create","kind":"row","id":"%s"},{"op":"create","kind":"row","id":"%s"}]}`, a, b))
	first := indexRead(t, s, "operator", IndexPage{By: "kind", Kind: "row", Limit: 1})
	wantIDs(t, first, a)
	if first.Cursor == "" {
		t.Fatal("no continuation")
	}
	done := make(chan error, 1)
	go func() {
		_, e := s.Apply("operator", []byte(fmt.Sprintf(`{"command_id":"change","expected":{"%s":{"revision":1,"topology":0}},"edits":[{"op":"delete","id":"%s"},{"op":"create","kind":"row","id":"%s"}]}`, b, b, c)), nil)
		done <- e
	}()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	next := indexRead(t, s, "operator", IndexPage{Cursor: first.Cursor})
	wantIDs(t, next, b)
	if next.Sequence != first.Sequence || next.Items[0].Revision != 1 {
		t.Fatal(next)
	}
	wantIDs(t, indexRead(t, s, "operator", IndexPage{By: "kind", Kind: "row"}), a, c)
	if _, e := s.IndexedPage("operator", IndexPage{Cursor: first.Cursor, Kind: "wrong"}); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
}

func TestBoundedCursorWalkWithTiesAndRotations(t *testing.T) {
	defs := []Index{{"label", "row", "label", "string"}}
	s, e := OpenIndexed(filepath.Join(t.TempDir(), "s"), "operator", defs, false)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	cmd := Command{ID: "seed"}
	var want []string
	for i := 0; i < 90; i++ {
		id := fmt.Sprintf("%064x", i)
		v := fmt.Sprintf(`"%c"`, 'a'+rune(i%3))
		cmd.Edits = append(cmd.Edits, Edit{Op: "create", Kind: "row", ID: id}, Edit{Op: "field", ID: id, Key: "label", Value: json.RawMessage(v)})
		if i%3 == 1 {
			want = append(want, id)
		}
	}
	b, e := json.Marshal(cmd)
	if e != nil {
		t.Fatal(e)
	}
	must(t, s, string(b))
	q := IndexPage{By: "key", Index: "label", Equal: json.RawMessage(`"b"`), Limit: 3}
	first := indexRead(t, s, "operator", q)
	got := rowIDs(first)
	one, zero := uint64(1), uint64(0)
	change := Command{ID: "remove", Expected: map[string]Expected{}}
	for i := 0; i < 75; i++ {
		id := fmt.Sprintf("%064x", i)
		change.Expected[id] = Expected{&one, &zero}
		change.Edits = append(change.Edits, Edit{Op: "delete", ID: id})
	}
	b, e = json.Marshal(change)
	if e != nil {
		t.Fatal(e)
	}
	must(t, s, string(b))
	for next := first; next.Cursor != ""; {
		next = indexRead(t, s, "operator", IndexPage{Cursor: next.Cursor, Limit: 3})
		got = append(got, rowIDs(next)...)
	}
	if !slices.Equal(got, want) {
		t.Fatal("unstable snapshot", got, want)
	}
	q.Limit = 50
	wantIDs(t, indexRead(t, s, "operator", q), want[25:]...)
}
