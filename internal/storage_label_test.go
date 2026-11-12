// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/internal/compat"
	"github.com/NeoTecDigital/LumberJack/types"
)

// The write side of the sealing labels (docs/extension-api.md §7.5, §7.8.4, §7.8.8; owner decision
// Q3(a)): legacy is the default, neutral is opt-in, a legacy store asked for neutral is rewrapped and
// written neutral, and neutral writes give the same records.

// An explicit storage configuration is the whole answer: the environment is not read.
func TestExplicitStorageConfigIgnoresTheEnvironment(t *testing.T) {
	t.Setenv("LUMBERJACK_STORAGE_MODE", "local-test")
	t.Setenv("LUMBERJACK_STORAGE_LOCAL_KEY_FILE", storageTestKey(t))
	dir := t.TempDir()
	config := types.ServerConfig{Process: types.ProcessInfo{Name: "explicit", DatabasePath: dir, LogPath: dir}, Storage: &types.StorageConfig{}}
	server, err := NewServer(config, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(t.Context())
	raw, err := os.ReadFile(server.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte(stateMagic)) {
		t.Fatal("an explicit plaintext configuration was sealed from the environment")
	}
}

func TestEncryptedFixturesWrittenNeutralGiveEqualRecords(t *testing.T) {
	for _, name := range []string{"enc-v3", "enc-v4"} {
		t.Run(name, func(t *testing.T) {
			entry := rollbackFixture(t, name)
			compatUseFixtureKey(t)
			t.Setenv("LUMBERJACK_STORAGE_WRITE_LABEL", types.StorageLabelNeutral)
			loaded := compatLoadEncrypted(t, compatRead(t, entry))
			dir := t.TempDir()
			path := filepath.Join(dir, "stock.dat")
			if err := os.WriteFile(path, compatRead(t, entry), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(StateLockPath(path), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			reloadServer(t, dir)
			rewritten, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if version, want := compatEnvelopeVersion(t, rewritten[len(encryptedStateMagic):]), map[string]int{"enc-v3": 5, "enc-v4": 6}[name]; version != want {
				t.Fatalf("written as envelope %d, want %d (neutral)", version, want)
			}
			t.Setenv("LUMBERJACK_STORAGE_WRITE_LABEL", types.StorageLabelLegacy)
			if again := compatLoadEncrypted(t, rewritten); !bytes.Equal(again, loaded) {
				t.Fatalf("the records changed across a neutral write at byte %d", compatFirstDifference(again, loaded))
			}
		})
	}
}

func rollbackFixture(t *testing.T, fixture string) compatManifestEntry {
	t.Helper()
	for _, entry := range compatManifest(t) {
		if entry.Fixture == fixture && entry.Kind != "tiered-log" {
			return entry
		}
	}
	t.Fatalf("no fixture %s", fixture)
	return compatManifestEntry{}
}

// A new object store is written under the label asked for: a version-1 key file and flag-1 records
// by default, a version-2 key file and flag-2 records when neutral; a version-1 store asked for
// neutral keeps its key file and appends flag 2.
func TestObjectStoreWritesTheLabelAskedFor(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 32)
	for _, label := range []compat.Label{compat.LabelLegacy, compat.LabelNeutral} {
		storage := &secureStorage{wrapper: &localStorageWrapper{key: key}, accounts: map[string]storageAccountKey{}, label: label}
		dir := filepath.Join(t.TempDir(), "store.objects")
		store := openTestStoreWith(t, dir, storage)
		receipt := mustPut(t, store, []byte("labelled"))
		wantVersion, wantFlag := compat.ObjectKeyFileLegacy, objectSealed
		if label == compat.LabelNeutral {
			wantVersion, wantFlag = compat.ObjectKeyFileNeutral, objectSealedNeutral
		}
		if version := objectKeyVersion(t, dir); version != wantVersion || store.sealer.writeFlag != wantFlag {
			t.Fatalf("label %d: key file %d, flag %d", label, version, store.sealer.writeFlag)
		}
		store.close()
		mustGet(t, openTestStoreWith(t, dir, storage), receipt.ID, []byte("labelled"))
	}
	legacy := &secureStorage{wrapper: &localStorageWrapper{key: key}, accounts: map[string]storageAccountKey{}}
	dir := filepath.Join(t.TempDir(), "store.objects")
	first := mustPut(t, openTestStoreWith(t, dir, legacy), []byte("flag one"))
	neutral := &secureStorage{wrapper: &localStorageWrapper{key: key}, accounts: map[string]storageAccountKey{}, label: compat.LabelNeutral}
	store := openTestStoreWith(t, dir, neutral)
	if store.sealer.writeFlag != objectSealedNeutral || objectKeyVersion(t, dir) != compat.ObjectKeyFileLegacy {
		t.Fatal("a version-1 store asked for neutral did not keep its key file and write flag 2")
	}
	second := mustPut(t, store, []byte("flag two"))
	mustGet(t, store, first.ID, []byte("flag one"))
	mustGet(t, store, second.ID, []byte("flag two"))
}

func objectKeyVersion(t *testing.T, dir string) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, objectKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	var envelope objectKeyEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Version
}
