// Written by Richard Christopher, Copyright 2026 NeoTec, LLC

//go:build rollbackwrite

package internal

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/compat"
	"github.com/NeoTecDigital/LumberJack/types"
)

// The writing half of the rollback check (docs/extension-api.md §7.8.6, `make rollback-check`). This
// build opens every fixture, writes an unrelated change, and leaves the store it wrote in
// $LJ_ROLLBACK_DIR with what the cut build must make of it: "open" (and every product field intact),
// or "refuse". The reading half runs at the cut, from internal/compat/rollback.

func TestWriteRollbackStores(t *testing.T) {
	out := os.Getenv("LJ_ROLLBACK_DIR")
	if out == "" {
		t.Skip("LJ_ROLLBACK_DIR names where the stores go; run through make rollback-check")
	}
	for _, entry := range compatManifest(t) {
		switch entry.Kind {
		case "plain", "encrypted", "nested":
			rollbackWrite(t, out, entry, compat.LabelLegacy, "open")
		case "tiered-snapshot":
			rollbackWriteTiered(t, out, entry)
		}
	}
	for _, name := range []string{"enc-v3", "enc-v4"} {
		rollbackWrite(t, out, rollbackEntry(t, name), compat.LabelNeutral, "refuse")
	}
	rollbackWriteObjects(t, out)
}

func rollbackEntry(t *testing.T, fixture string) compatManifestEntry {
	t.Helper()
	for _, entry := range compatManifest(t) {
		if entry.Fixture == fixture && entry.Kind != "tiered-log" {
			return entry
		}
	}
	t.Fatalf("no fixture %s", fixture)
	return compatManifestEntry{}
}

// rollbackWrite opens a fixture as a stock store, adds a node under the root, persists it under the
// label, and leaves the state file and its expectation in out.
func rollbackWrite(t *testing.T, out string, entry compatManifestEntry, label compat.Label, expect string) {
	t.Helper()
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	if entry.Kind == "encrypted" {
		compatUseFixtureKey(t)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "stock.dat")
	if err := os.WriteFile(path, compatRead(t, entry), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(StateLockPath(path), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	server := reloadServer(t, dir)
	if server.storage != nil {
		if err := server.storage.relabel(context.Background(), label); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.changeForest(addRootChild(server, "rollback-probe")); err != nil {
		t.Fatal(err)
	}
	_ = server.Shutdown(context.Background())
	name := entry.Fixture
	if label == compat.LabelNeutral {
		name += "-neutral"
	}
	rollbackKeep(t, out, name, expect, map[string]string{"": path})
}

// rollbackWriteTiered opens the tiered fixture tiered, writes, and shuts down cleanly, which folds
// the log into the state file.
func rollbackWriteTiered(t *testing.T, out string, entry compatManifestEntry) {
	t.Helper()
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	config := tieredConfig(t, types.HotSyncCommit)
	statePath := StatePath(config)
	matches, _ := filepath.Glob(filepath.Join(compatFixtureDir, entry.File) + "*")
	for _, from := range matches {
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		suffix := strings.TrimPrefix(from, filepath.Join(compatFixtureDir, entry.File))
		if err := os.WriteFile(statePath+suffix, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	server, err := LoadServer(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.changeForest(addRootChild(server, "rollback-probe")); err != nil {
		t.Fatal(err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"": statePath}
	segments, _ := filepath.Glob(statePath + ".log.*")
	for _, segment := range segments {
		files[strings.TrimPrefix(segment, statePath)] = segment
	}
	rollbackKeep(t, out, entry.Fixture, "open", files)
}

// rollbackWriteObjects adds a flag-2 record to the sealed fixture's segment. The cut build reads
// its flag-1 records and refuses the flag-2 one.
func rollbackWriteObjects(t *testing.T, out string) {
	t.Helper()
	key := compatUseFixtureKey(t)
	dir := filepath.Join(out, "objects-sealed-v1.objects")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, entry := range compatManifest(t) {
		if entry.Kind == "objects" {
			if err := os.WriteFile(filepath.Join(dir, filepath.Base(entry.File)), compatRead(t, entry), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	store := openTestStoreWith(t, dir, &secureStorage{wrapper: &localStorageWrapper{key: key}, accounts: map[string]storageAccountKey{}})
	store.sealer.writeFlag = objectSealedNeutral
	mustPut(t, store, []byte("a record the cut build cannot open"))
	store.close()
	if err := os.WriteFile(filepath.Join(out, "objects-sealed-v1.expect"), []byte("flag2"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rollbackKeep(t *testing.T, out, name, expect string, files map[string]string) {
	t.Helper()
	for suffix, from := range files {
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, name+".ljstate"+suffix), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(out, name+".expect"), []byte(expect), 0o600); err != nil {
		t.Fatal(err)
	}
}
