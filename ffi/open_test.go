// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// Open's two refusals at the seam the C boundary maps them through.
//
// These are ordinary Go tests because cgo is not supported in test files — no lj_cstr can be built
// here — so ic_lj_open and ic_lj_adopt themselves are driven from ffi/ctest/smoke.c, one with a
// second process holding the flock. What THIS proves is the mapping those exports call: a real
// refusal out of embedded, through openStatus and adoptStatus, to the status the header documents.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/NeoTecDigital/LumberJack/embedded"
	"github.com/NeoTecDigital/LumberJack/types"
)

// A missing sidecar is LJ_UNGUARDED and NEVER LJ_LOCKED. LJ_LOCKED is documented as retry-and-back-
// off; a C caller handed it for a condition only a human can clear retries forever. Adoption maps
// through too: LJ_OK once, LJ_CONFLICT after, LJ_NOT_FOUND where there is no state file.
func TestOpenStatusKeepsUnguardedApartFromLocked(t *testing.T) {
	dir := t.TempDir()
	const name = "ffi_open_test"
	cfg := embedded.Config{Process: types.ProcessInfo{Name: name, DatabasePath: dir}}

	first, err := embedded.Open(cfg, "system")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := first.CreateNode(embedded.CreateNodeRequest{Path: "work/legacy", Type: "leaf"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The sidecar the runtime minted, found rather than restated: without it this is a forest from
	// before the sidecar existed.
	sidecars, err := filepath.Glob(filepath.Join(dir, "*.lock"))
	if err != nil || len(sidecars) != 1 {
		t.Fatalf("expected exactly one sidecar beside the state file, found %v (%v)", sidecars, err)
	}
	if err := os.Remove(sidecars[0]); err != nil {
		t.Fatalf("remove the sidecar: %v", err)
	}

	_, err = embedded.Open(cfg, "system")
	if err == nil {
		t.Fatal("Open succeeded over a state file with no sidecar")
	}
	if got := openStatus(err); got != statusUnguarded {
		t.Fatalf("openStatus(%v) = %d, want LJ_UNGUARDED (%d)", err, got, statusUnguarded)
	}
	if openStatus(err) == statusLocked {
		t.Fatal("a missing sidecar mapped to LJ_LOCKED, the status a caller retries forever")
	}

	// The transient refusal keeps its own status, wrapped or bare.
	if got := openStatus(fmt.Errorf("wrapped: %w", embedded.ErrLocked)); got != statusLocked {
		t.Fatalf("openStatus(ErrLocked) = %d, want LJ_LOCKED (%d)", got, statusLocked)
	}
	if got := openStatus(nil); got != statusOK {
		t.Fatalf("openStatus(nil) = %d, want LJ_OK", got)
	}

	if got := adoptStatus(embedded.AdoptPath(t.TempDir(), "nothing")); got != statusNotFound {
		t.Fatalf("adopt with no state file = %d, want LJ_NOT_FOUND (%d)", got, statusNotFound)
	}
	if got := adoptStatus(embedded.AdoptPath(dir, name)); got != statusOK {
		t.Fatalf("adopt = %d, want LJ_OK", got)
	}
	if got := adoptStatus(embedded.AdoptPath(dir, name)); got != statusConflict {
		t.Fatalf("a second adopt = %d, want LJ_CONFLICT (%d): adoption is one-shot", got, statusConflict)
	}

	second, err := embedded.Open(cfg, "system")
	if got := openStatus(err); got != statusOK {
		t.Fatalf("Open after adopt = %d (%v), want LJ_OK", got, err)
	}
	defer second.Close()
	if _, err := second.StatusOf("work/legacy"); err != nil {
		t.Fatalf("the adopted forest lost work/legacy: %v", err)
	}
}
