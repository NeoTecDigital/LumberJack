// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/store"
)

func applyIndexCommand(t *testing.T, h *RecordHandle, q string) {
	t.Helper()
	if _, e := h.Apply([]byte(q)); e != nil {
		t.Fatal(e)
	}
}
func TestIndexedReaderRevocationAndScopedEdges(t *testing.T) {
	dir := t.TempDir()
	o, e := OpenIndexedRecords(dir, "s", "owner", nil, false)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()

	raw, e := o.Apply([]byte(`{"command_id":"seed","expected":{"root":{"revision":0}},"edits":[{"op":"create","kind":"red"},{"op":"create","kind":"red"},{"op":"create","kind":"blue"},{"op":"link","parent":"$2","child":"$0"},{"op":"grant_read","principal":"reader","kind":"red"}]}`))
	if e != nil {
		t.Fatal(e)
	}
	var receipt struct{ Created []string }
	if e = json.Unmarshal(raw, &receipt); e != nil {
		t.Fatal(e)
	}
	r, e := OpenIndexedRecords(dir, "s", "reader", nil, true)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if _, e = r.Apply([]byte(`{}`)); !errors.Is(e, store.ErrDenied) {
		t.Fatal("write from reader", e)
	}
	raw, e = r.IndexedPage([]byte(`{"by":"kind","kind":"red","limit":1}`))
	if e != nil {
		t.Fatal(e)
	}
	var page struct{ Cursor string }
	if e = json.Unmarshal(raw, &page); e != nil || page.Cursor == "" {
		t.Fatal(e)
	}
	denied := func(q string, why error) {
		t.Helper()
		if _, e := r.IndexedPage([]byte(q)); !errors.Is(e, why) {
			t.Fatal(q, e)
		}
	}
	denied(`{"by":"kind","kind":"blue"}`, store.ErrDenied)
	denied(fmt.Sprintf(`{"by":"parents","id":"%s","kind":"blue"}`, receipt.Created[0]), store.ErrDenied)
	denied(fmt.Sprintf(`{"by":"children","id":"%s","kind":"red"}`, receipt.Created[2]), store.ErrAbsent)
	denied(fmt.Sprintf(`{"by":"id","id":"%s"}`, receipt.Created[2]), store.ErrAbsent)
	if _, e = r.IndexedPage([]byte(fmt.Sprintf(`{"by":"id","id":"%s"}`, receipt.Created[0]))); e != nil {
		t.Fatal(e)
	}
	cursor := fmt.Sprintf(`{"cursor":%q}`, page.Cursor)
	applyIndexCommand(t, o, `{"command_id":"revoke","expected":{"root":{"revision":1}},"edits":[{"op":"revoke_read","principal":"reader","kind":"red"}]}`)
	denied(cursor, store.ErrDenied)
	applyIndexCommand(t, o, `{"command_id":"restore","expected":{"root":{"revision":2}},"edits":[{"op":"grant_read","principal":"reader","kind":"red"}]}`)
	denied(cursor, store.ErrDenied)
}
