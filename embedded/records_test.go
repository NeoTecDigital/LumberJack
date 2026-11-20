// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/store"
)

func TestRecordOpenSeparatesProfilesAndDoesNotRewrite(t *testing.T) {
	cfg := embeddedConfig(t)
	dir, name := cfg.Process.DatabasePath, cfg.Process.Name
	legacy, e := Open(cfg, "system")
	if e != nil {
		t.Fatal(e)
	}
	if e = legacy.Close(); e != nil {
		t.Fatal(e)
	}
	if r, e := OpenRecords(dir, name, "owner"); e == nil {
		r.Close()
		t.Fatal("record open adopted legacy store")
	}
	dir = t.TempDir()
	cfg.Process.DatabasePath = dir
	r, e := OpenRecords(dir, name, "owner")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Apply([]byte(`{"command_id":"a","edits":[{"op":"create","kind":"item"}]}`)); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	stamp := time.Unix(1234, 0)
	files, e := filepath.Glob(filepath.Join(dir, name+".dat*"))
	if e != nil {
		t.Fatal(e)
	}
	if len(files) < 3 {
		t.Fatal("missing marker, lock or log")
	}
	originals := map[string][]byte{}
	for _, p := range files {
		if e = os.Chtimes(p, stamp, stamp); e != nil {
			t.Fatal(e)
		}
		originals[p], e = os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
	}
	if _, e := OpenRecords(dir, name, "other"); !errors.Is(e, store.ErrDenied) {
		t.Fatal(e)
	}
	if bad, e := Open(cfg, "system"); e == nil {
		bad.Close()
		t.Fatal("legacy open adopted record store")
	}
	r, e = OpenRecords(dir, name, "owner")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Page([]byte(`{"by":"kind","kind":"item"}`)); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	after, e := filepath.Glob(filepath.Join(dir, name+".dat*"))
	if e != nil || len(after) != len(files) {
		t.Fatal(after, e)
	}
	for _, p := range after {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		st, e := os.Stat(p)
		if e != nil || !st.ModTime().Equal(stamp) || !bytes.Equal(b, originals[p]) {
			t.Fatal("populated open wrote", p, e)
		}
	}
}
