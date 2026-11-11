// Written by Richard Christopher, Copyright 2026 Richard Christopher

package embedded

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/types"
)

// The embedded runtime reads `<DatabasePath>/config.yaml`: a host opts into tiered persistence by
// writing the persistence block there, with no change to how it opens the forest.
func TestAHostOptsIntoTieredPersistenceThroughTheStoresConfigFile(t *testing.T) {
	dir := t.TempDir()
	config := "persistence:\n  mode: tiered\n  hot_sync: commit\n"
	if err := os.WriteFile(filepath.Join(dir, types.StoreConfigFile), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	handle, err := Open(configOver(dir), "system")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := handle.CreateNode(CreateNodeRequest{Path: "work/alpha", Type: "leaf"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	segments, _ := filepath.Glob(filepath.Join(dir, "embedded_test.dat.log.*"))
	if len(segments) != 1 {
		t.Fatalf("expected one log segment beside the state file, found %v", segments)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	// A clean close writes the state file and trims the log the file covers.
	if _, err := os.Stat(filepath.Join(dir, "embedded_test.dat")); err != nil {
		t.Fatalf("state file after close: %v", err)
	}
	segments, _ = filepath.Glob(filepath.Join(dir, "embedded_test.dat.log.*"))
	if len(segments) != 0 {
		t.Fatalf("segments left after a clean close: %v", segments)
	}
	reopened, err := Open(configOver(dir), "system")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.StatusOf("work/alpha"); err != nil {
		t.Fatalf("the node did not survive the reopen: %v", err)
	}
}

func TestAMisconfiguredStoreFileRefusesToOpen(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, types.StoreConfigFile), []byte("sync:\n  role: replica\n  primary: host:1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(configOver(dir), "system")
	if err == nil || !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("replica role: %v", err)
	}
}
