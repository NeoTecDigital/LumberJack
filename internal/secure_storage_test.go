// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// Observed red before implementation (2026-09-21): "legacy load must require
// explicit migration, got <nil>" and "state is not an authenticated encrypted envelope".

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func storageTestKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wrapping.key")
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEncryptedStorageRequiresOptInToMigrate(t *testing.T) {
	config := coreConfig()
	config.Process.DatabasePath = t.TempDir()
	s, err := NewCore(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.persistState(s.statePath()); err != nil {
		t.Fatal(err)
	}
	s.Shutdown(context.Background())
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", storageTestKey(t))
	loaded, err := NewCore(config)
	if loaded != nil {
		loaded.Shutdown(context.Background())
	}
	if err == nil || !strings.Contains(err.Error(), "migration") {
		t.Fatalf("legacy load must require explicit migration, got %v", err)
	}
}

func TestEncryptedStorageRoundTripAndWrongKey(t *testing.T) {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", storageTestKey(t))
	config := coreConfig()
	config.Process.DatabasePath = t.TempDir()
	s, err := NewCore(config)
	if err != nil {
		t.Fatal(err)
	}
	s.forest.Name = "private title must survive"
	if err = s.persistState(s.statePath()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("LUMBERJACK-ENCRYPTED-STATE-3\n")) {
		t.Fatal("state is not an authenticated encrypted envelope")
	}
	s.Shutdown(context.Background())
	loaded, err := NewCore(config)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.forest.Name != "private title must survive" {
		t.Fatal("round trip lost private content")
	}
	loaded.Shutdown(context.Background())
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", storageTestKey(t))
	wrong, err := NewCore(config)
	if wrong != nil {
		wrong.Shutdown(context.Background())
	}
	if err == nil {
		t.Fatal("wrong wrapping key accepted")
	}
}
