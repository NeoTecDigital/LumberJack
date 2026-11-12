// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
	"lukechampine.com/blake3"
)

// The state files the cut build wrote, read back by this build. They are generated once, at the
// cut, by compat_fixtures_gen_test.go (build tag compatgen), and never regenerated: they are the
// stores that exist in the field. See docs/extension-api.md §7.7.

const (
	compatFixtureDir   = "compat/testdata"
	compatManifestName = "MANIFEST.jsonl"
)

// compatObjectBodies are the plaintexts the objects-sealed-v1 fixture holds.
var compatObjectBodies = []string{"first sealed object", "second sealed object", strings.Repeat("third ", 64)}

// compatManifestEntry is one fixture file. ReencodeSHA256 is what the cut build wrote back after
// loading a plaintext document: it differs from DocumentSHA256 where a product stored a typed value
// (a receipt struct) that comes back as a map and re-marshals with its keys sorted. LoadedSHA256 pins what a load produces where the file is
// not itself the document: the node-table re-encoding of a nested file, of a tiered store after
// replay, and of an encrypted store after it is opened.
type compatManifestEntry struct {
	Fixture        string `json:"fixture"`
	File           string `json:"file"`
	Kind           string `json:"kind"`
	SHA256         string `json:"sha256"`
	Bytes          int    `json:"bytes"`
	Banner         string `json:"banner,omitempty"`
	DocumentSHA256 string `json:"document_sha256,omitempty"`
	ReencodeSHA256 string `json:"reencode_sha256,omitempty"`
	LoadedSHA256   string `json:"loaded_sha256,omitempty"`
	Contains       string `json:"contains"`
}

func compatHex(sum []byte) string { return hex.EncodeToString(sum) }

func compatSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return compatHex(sum[:])
}

// compatPlainDocument opens banner ‖ sha256 ‖ gzip(document) and answers the document the header
// vouches for, with the banner it carried.
func compatPlainDocument(data []byte) ([]byte, string, error) {
	if len(data) < len(stateMagic)+sha256.Size || !isStateBanner(data[:len(stateMagic)]) {
		return nil, "", fmt.Errorf("no state banner")
	}
	banner := string(data[:len(stateMagic)])
	hash := data[len(stateMagic) : len(stateMagic)+sha256.Size]
	document, err := readCappedGzip(bytes.NewReader(data[len(stateMagic)+sha256.Size:]), maxDecompressedState)
	if err != nil {
		return nil, "", err
	}
	if sum := sha256.Sum256(document); !bytes.Equal(sum[:], hash) {
		return nil, "", fmt.Errorf("header hash does not vouch for the document")
	}
	return document, banner, nil
}

func compatManifest(t *testing.T) []compatManifestEntry {
	t.Helper()
	file, err := os.Open(filepath.Join(compatFixtureDir, compatManifestName))
	if err != nil {
		t.Fatalf("the compatibility fixtures are missing: %v", err)
	}
	defer file.Close()
	var entries []compatManifestEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry compatManifestEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("manifest line %q: %v", scanner.Text(), err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return entries
}

func compatRead(t *testing.T, entry compatManifestEntry) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(compatFixtureDir, entry.File))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// compatKeyFile copies the fixture wrapping key to a private file, since a checkout cannot carry
// the 0600 mode the local-test wrapper insists on, and selects local-test storage with it.
func compatUseFixtureKey(t *testing.T) []byte {
	t.Helper()
	key, err := os.ReadFile(filepath.Join(compatFixtureDir, "local-test.key"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "local-test.key")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", path)
	return key
}

// compatLoadedDocument is the node-table encoding of what this build loads from a fixture that is
// not itself a node-table document.
func compatLoadedDocument(t *testing.T, entry compatManifestEntry, data []byte) []byte {
	t.Helper()
	switch entry.Kind {
	case "nested":
		return compatLoadNested(t, data)
	case "encrypted":
		return compatLoadEncrypted(t, data)
	case "tiered-snapshot":
		return compatLoadTiered(t, entry)
	}
	t.Fatalf("%s: no load for kind %q", entry.File, entry.Kind)
	return nil
}

func compatLoadNested(t *testing.T, data []byte) []byte {
	t.Helper()
	server := stagedTestServer(t, t.TempDir())
	payload, err := server.readSealedPayload(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	forest, err := server.readNestedState(payload)
	if err != nil {
		t.Fatal(err)
	}
	return compatEncode(t, forest, 0)
}

func compatLoadEncrypted(t *testing.T, data []byte) []byte {
	t.Helper()
	compatUseFixtureKey(t)
	server := stagedTestServer(t, t.TempDir())
	path := filepath.Join(t.TempDir(), "enc.ljstate")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	forest, encrypted, err := server.readEncryptedState(file)
	if err != nil || !encrypted {
		t.Fatalf("encrypted fixture did not open: encrypted=%v %v", encrypted, err)
	}
	return compatEncode(t, forest, 0)
}

// compatLoadTiered opens the snapshot and its hot log as a tiered store would, replay included.
func compatLoadTiered(t *testing.T, entry compatManifestEntry) []byte {
	t.Helper()
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	config := tieredConfig(t, types.HotSyncCommit)
	statePath := StatePath(config)
	matches, err := filepath.Glob(filepath.Join(compatFixtureDir, entry.File) + "*")
	if err != nil {
		t.Fatal(err)
	}
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
		t.Fatalf("tiered fixture did not open: %v", err)
	}
	defer server.Shutdown(context.Background())
	server.forestMutex.RLock()
	defer server.forestMutex.RUnlock()
	return compatEncode(t, server.forest, 0)
}

func compatEncode(t *testing.T, forest *core.Node, sequence uint64) []byte {
	t.Helper()
	data, err := encodeStateAt(forest, sequence)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Every fixture file is the file the manifest names, byte for byte, and every file is named.
func TestCompatFixtureManifestHashes(t *testing.T) {
	entries := compatManifest(t)
	listed := map[string]bool{compatManifestName: true}
	for _, entry := range entries {
		data := compatRead(t, entry)
		if got := compatSHA(data); got != entry.SHA256 || len(data) != entry.Bytes {
			t.Errorf("%s: sha256 %s (%d bytes), manifest says %s (%d bytes)", entry.File, got, len(data), entry.SHA256, entry.Bytes)
		}
		listed[entry.File] = true
	}
	var stray []string
	err := filepath.WalkDir(compatFixtureDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		name, _ := filepath.Rel(compatFixtureDir, path)
		if !listed[filepath.ToSlash(name)] {
			stray = append(stray, name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(stray)
	if len(stray) != 0 {
		t.Fatalf("fixture files the manifest does not name: %v", stray)
	}
}

// compatReencode decodes a plaintext document, links it and encodes it again, as a load followed by
// an unrelated persist would.
func compatReencode(t *testing.T, document []byte) []byte {
	t.Helper()
	table, err := decodeTable(document)
	if err != nil {
		t.Fatal(err)
	}
	forest, err := linkTable(table)
	if err != nil {
		t.Fatal(err)
	}
	return compatEncode(t, forest, table.LogSequence)
}

// A plaintext store re-encodes to the identical document, so its header hash is unchanged and the
// writer's unchanged-skip does not even rewrite it (§7.8.1). The cut build did not: it re-marshalled
// receipts a product stored as structs with their keys sorted (ReencodeSHA256 records what it wrote).
// This build writes an unchanged node back as the bytes it was read from. The re-encoding is also a
// fixed point.
func TestCompatPlainFixturesReencodeByteIdentically(t *testing.T) {
	for _, entry := range compatManifest(t) {
		if entry.Kind != "plain" && entry.Kind != "tiered-snapshot" {
			continue
		}
		t.Run(entry.Fixture, func(t *testing.T) {
			document, banner, err := compatPlainDocument(compatRead(t, entry))
			if err != nil {
				t.Fatal(err)
			}
			if compatSHA(document) != entry.DocumentSHA256 || !strings.HasPrefix(banner, entry.Banner) {
				t.Fatalf("document or banner differs from the manifest")
			}
			again := compatReencode(t, document)
			if !bytes.Equal(again, document) {
				t.Fatalf("re-encoding drifted at byte %d", compatFirstDifference(again, document))
			}
			if fixed := compatReencode(t, compatReencode(t, again)); !bytes.Equal(fixed, again) {
				t.Fatalf("re-encoding is not a fixed point: drifts at byte %d", compatFirstDifference(fixed, again))
			}
		})
	}
}

// What a load produces from a nested, encrypted or tiered fixture is pinned by its hash.
func TestCompatLoadedFixturesArePinned(t *testing.T) {
	for _, entry := range compatManifest(t) {
		if entry.LoadedSHA256 == "" {
			continue
		}
		t.Run(entry.Fixture, func(t *testing.T) {
			loaded := compatLoadedDocument(t, entry, compatRead(t, entry))
			if got := compatSHA(loaded); got != entry.LoadedSHA256 {
				t.Fatalf("loaded document %s, manifest says %s", got, entry.LoadedSHA256)
			}
		})
	}
}

// The sealed object fixture reads back every object it was written with.
func TestCompatSealedObjectsRead(t *testing.T) {
	key := compatUseFixtureKey(t)
	dir := filepath.Join(t.TempDir(), "store.objects")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, entry := range compatManifest(t) {
		if entry.Kind != "objects" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(entry.File)), compatRead(t, entry), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	storage := &secureStorage{wrapper: &localStorageWrapper{key: key}, accounts: map[string]storageAccountKey{}}
	store, err := openObjectStore(dir, 1<<20, storage)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if store.count() != len(compatObjectBodies) {
		t.Fatalf("store holds %d objects, want %d", store.count(), len(compatObjectBodies))
	}
	for _, body := range compatObjectBodies {
		id := objectID(blake3.Sum256([]byte(body)))
		got, err := store.get(id)
		if err != nil || string(got) != body {
			t.Fatalf("object %s: %q, %v", id.hex(), got, err)
		}
	}
}

func compatFirstDifference(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}
