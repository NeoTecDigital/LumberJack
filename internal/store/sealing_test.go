// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"bytes"
	"crypto/rand"
	"errors"
	"github.com/NeoTecDigital/LumberJack/internal/persist"
	"github.com/NeoTecDigital/LumberJack/types"
	"os"
	"path/filepath"
	"testing"
)

func testPolicy(t *testing.T) *types.StorageConfig {
	k := make([]byte, 32)
	rand.Read(k)
	path := filepath.Join(t.TempDir(), "fixture.wrap")
	if err := os.WriteFile(path, k, 0600); err != nil {
		t.Fatal(err)
	}
	return &types.StorageConfig{Mode: "local-test", LocalKeyFile: path}
}
func sealedJournal(t *testing.T, cfg *types.StorageConfig) (string, []persist.Record) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.dat")
	s, e := OpenWithStorage(path, "operator", nil, false, cfg)
	if e != nil {
		t.Fatal(e)
	}
	must(t, s, `{"command_id":"first-private","edits":[{"op":"create","kind":"private-item"}]}`)
	must(t, s, `{"command_id":"next-private","edits":[{"op":"create","kind":"private-item"}]}`)
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(path)
	if e != nil || !bytes.HasPrefix(b, []byte(sealedBanner)) || bytes.Contains(b, []byte("receipt_key")) {
		t.Fatal("unprotected marker")
	}
	rs, e := persist.Inspect(path)
	if e != nil || len(rs) != 2 || bytes.Contains(rs[0].Body, []byte("private-item")) {
		t.Fatal("unprotected frames", e)
	}
	return path, rs
}
func TestSealedFrameBinding(t *testing.T) {
	cfg := testPolicy(t)
	_, other := sealedJournal(t, cfg)
	for _, change := range []string{"reorder", "replay", "move"} {
		t.Run(change, func(t *testing.T) {
			p, rs := sealedJournal(t, cfg)
			parts, _ := filepath.Glob(p + ".log.*")
			for _, part := range parts {
				if e := os.Remove(part); e != nil {
					t.Fatal(e)
				}
			}
			switch change {
			case "reorder":
				rs[0].Body, rs[1].Body = rs[1].Body, rs[0].Body
			case "replay":
				rs[1].Body = rs[0].Body
			case "move":
				rs[0].Body = other[0].Body
			}
			// Provide a well-formed sequential outer log; detection must come from authenticated frames.
			if e := writeFrames(p, nil, rs); e != nil {
				t.Fatal(e)
			}
			if _, e := OpenWithStorage(p, "operator", nil, false, cfg); !errors.Is(e, types.ErrSealingLabel) {
				t.Fatal(change, e)
			}
		})
	}
}
func TestSealedMarkerRequiresWrapperAndLabel(t *testing.T) {
	cfg := testPolicy(t)
	cfg.Labels = []types.SealingLabel{{Name: "fixture", StatePrefix: "fixture/state/", ObjectsPrefix: "fixture/objects/"}}
	cfg.WriteLabel = "fixture"
	p, _ := sealedJournal(t, cfg)
	wrong := *cfg
	wrong.Labels = nil
	wrong.WriteLabel = ""
	for _, other := range []*types.StorageConfig{nil, &wrong, testPolicy(t)} {
		if _, e := OpenWithStorage(p, "operator", nil, false, other); !errors.Is(e, types.ErrSealingLabel) {
			t.Fatal(e)
		}
	}
	reopened, e := OpenWithStorage(p, "operator", nil, false, cfg)
	if e != nil {
		t.Fatal(e)
	}
	reopened.Close()
}
