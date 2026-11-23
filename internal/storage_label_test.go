// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/NeoTecDigital/LumberJack/internal/keywrap"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
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
			reloadWithStorage(t, dir, cutStorageConfig(t))
			rewritten, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if version, want := compatEnvelopeVersion(t, rewritten[len(encryptedStateMagic):]), map[string]int{"enc-v3": 5, "enc-v4": 6}[name]; version != want {
				t.Fatalf("written as envelope %d, want %d (neutral)", version, want)
			}
			t.Setenv("LUMBERJACK_STORAGE_WRITE_LABEL", "fixture")
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
// for a host, a version-2 key file and flag-2 records by default; a version-1 store asked for
// neutral keeps its key file and appends flag 2.
func TestObjectStoreWritesTheLabelAskedFor(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 32)
	for _, label := range []compat.Label{cutLabel(t), (compat.Label{})} {
		storage := &secureStorage{wrapper: &keywrap.Local{Key: key}, accounts: map[string]storageAccountKey{}, label: label, labels: []compat.Label{label}}
		dir := filepath.Join(t.TempDir(), "store.objects")
		store := openTestStoreWith(t, dir, storage)
		receipt := mustPut(t, store, []byte("labelled"))
		wantVersion, wantFlag := compat.ObjectKeyFileLegacy, objectSealed
		if label == (compat.Label{}) {
			wantVersion, wantFlag = compat.ObjectKeyFileNeutral, objectSealedNeutral
		}
		if version := objectKeyVersion(t, dir); version != wantVersion || store.sealer.writeFlag != wantFlag {
			t.Fatalf("label %v: key file %d, flag %d", label, version, store.sealer.writeFlag)
		}
		store.close()
		mustGet(t, openTestStoreWith(t, dir, storage), receipt.ID, []byte("labelled"))
	}
	legacy := cutStorage(t, key)
	dir := filepath.Join(t.TempDir(), "store.objects")
	first := mustPut(t, openTestStoreWith(t, dir, legacy), []byte("flag one"))
	neutral := &secureStorage{wrapper: &keywrap.Local{Key: key}, accounts: map[string]storageAccountKey{}, labels: []compat.Label{cutLabel(t)}}
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

// Exercise both separately authenticated artifacts, not just the state envelope.
func TestHostSealingLabelsRoundTripAndRefuseWithoutWriting(t *testing.T) {
	host := types.SealingLabel{Name: "example", StatePrefix: "example/state/", ObjectsPrefix: "example/objects/"}
	cfg := coreConfig()
	cfg.Process.DatabasePath = t.TempDir()
	policy := types.StorageConfig{Mode: "local-test", LocalKeyFile: storageTestKey(t), Labels: []types.SealingLabel{host}, WriteLabel: host.Name}
	cfg.Storage = &policy
	s, err := NewCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.EnsureSystemUser(); err != nil {
		t.Fatal(err)
	}
	codec, err := s.storageCodec()
	if err != nil {
		t.Fatal(err)
	}
	objects := openTestStoreWith(t, ObjectsPath(cfg), codec)
	receipt := mustPut(t, objects, []byte("fixture object"))
	objects.close()
	statePath := s.statePath()
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if encryptedEnvelopeVersion(t, statePath) != 3 || objectKeyVersion(t, ObjectsPath(cfg)) != 1 {
		t.Fatal("host format changed")
	}
	want := sealedTree(t, cfg.Process.DatabasePath)
	for _, labels := range [][]types.SealingLabel{nil, {{Name: "example", StatePrefix: "wrong/", ObjectsPrefix: host.ObjectsPrefix}}, {{Name: "example", StatePrefix: host.StatePrefix, ObjectsPrefix: "wrong/"}}, {{Name: "first", StatePrefix: host.StatePrefix, ObjectsPrefix: "wrong/"}, {Name: "second", StatePrefix: "wrong-state/", ObjectsPrefix: host.ObjectsPrefix}}} {
		policy.Labels, policy.WriteLabel = labels, types.StorageLabelNeutral // even an explicit relabel must not write on refusal
		if got, err := NewCore(cfg); got != nil || !errors.Is(err, ErrSealingLabel) {
			t.Fatalf("want named label refusal, got %v", err)
		}
		if !reflect.DeepEqual(want, sealedTree(t, cfg.Process.DatabasePath)) {
			t.Fatal("refusal changed the store")
		}
	}
	policy.Labels = []types.SealingLabel{{Name: "another", StatePrefix: "other/state/", ObjectsPrefix: "other/objects/"}, host}
	policy.WriteLabel = "" // registering a reader is not a request to migrate existing bytes
	s, err = NewCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	codec, err = s.storageCodec()
	if err != nil {
		t.Fatal(err)
	}
	objects = openTestStoreWith(t, ObjectsPath(cfg), codec)
	mustGet(t, objects, receipt.ID, []byte("fixture object"))
	objects.close()
	if err := s.persistState(statePath); err != nil {
		t.Fatal(err)
	}
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if encryptedEnvelopeVersion(t, statePath) != 3 {
		t.Fatal("opening with host label changed wire version")
	}
	s, err = NewCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(t.Context())
}

func sealedTree(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	got := map[string][32]byte{}
	err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err == nil {
			got[path] = sha256.Sum256(raw)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}
