// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"github.com/NeoTecDigital/LumberJack/types"
	"os"
	"testing"
	"time"
)

func TestPopulatedEnsureDoesNotPersist(t *testing.T) {
	cfg := types.ServerConfig{Process: types.ProcessInfo{DatabasePath: t.TempDir(), Name: "open"}}
	s, err := NewCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(t.Context())
	if seeded, err := s.EnsureSystemUser(); err != nil || !seeded {
		t.Fatalf("seed: %v %v", seeded, err)
	}
	path := StatePath(cfg)
	fixed := time.Unix(100, 0)
	if err := os.Chtimes(path, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	if seeded, err := s.EnsureSystemUser(); err != nil || seeded {
		t.Fatalf("reopen: %v %v", seeded, err)
	}
	st, err := os.Stat(path)
	if err != nil || !st.ModTime().Equal(fixed) {
		t.Fatalf("populated open wrote state: %v", err)
	}
}
