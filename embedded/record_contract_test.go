// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/embedded"
	"github.com/NeoTecDigital/LumberJack/extension"
)

type recordPermit struct{ outcomes []extension.Outcome }

func (*recordPermit) WantsRevision() bool          { return true }
func (p *recordPermit) Settle(o extension.Outcome) { p.outcomes = append(p.outcomes, o) }

func TestPublicRecordErrors(t *testing.T) {
	dir := t.TempDir()
	h, err := embedded.OpenRecords(dir, "data", "owner")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if _, err = embedded.OpenRecords(dir, "data", "other"); !errors.Is(err, embedded.ErrRecordDenied) {
		t.Fatal(err)
	}
	if _, err = h.Apply([]byte("{}")); !errors.Is(err, embedded.ErrRecordInvalid) {
		t.Fatal(err)
	}
	if _, err = h.Page([]byte(`{"by":"id","id":"` + strings.Repeat("b", 64) + `"}`)); !errors.Is(err, embedded.ErrRecordAbsent) {
		t.Fatal(err)
	}
	if _, err = h.Page([]byte(`{"by":"kind","kind":"unit","sequence":9}`)); !errors.Is(err, embedded.ErrRecordConflict) {
		t.Fatal(err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	p := new(recordPermit)
	if _, err = h.ApplyPermitted([]byte("{}"), p); !errors.Is(err, embedded.ErrRecordUnavailable) {
		t.Fatal(err)
	}
	if len(p.outcomes) != 1 {
		t.Fatalf("settlements: %d", len(p.outcomes))
	}
	o := p.outcomes[0]
	if o.State != extension.WriteUnknown || o.Unchanged || o.Commit != (extension.Commit{}) || !errors.Is(o.Err, embedded.ErrRecordUnavailable) {
		t.Fatalf("settlement: %+v", o)
	}
}
