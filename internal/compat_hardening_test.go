// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/internal/compat"
	"lukechampine.com/blake3"
)

// The read side of compatibility hardening (docs/extension-api.md §7.8.2, §7.8.5, §7.8.8).

func compatRecords(t *testing.T, document []byte) (string, map[string]map[string]json.RawMessage, map[string]json.RawMessage) {
	t.Helper()
	var table struct {
		Root  string                     `json:"root"`
		Nodes map[string]json.RawMessage `json:"nodes"`
	}
	if err := json.Unmarshal(document, &table); err != nil {
		t.Fatal(err)
	}
	keyed := map[string]map[string]json.RawMessage{}
	for id, raw := range table.Nodes {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		keyed[id] = fields
	}
	return table.Root, keyed, table.Nodes
}

// Every key's bytes in every fixture survive a write of an unrelated change: a node added under the
// root changes the root's children and nothing else (§7.8.2).
func TestCompatEveryKeySurvivesAnUnrelatedWrite(t *testing.T) {
	for _, entry := range compatManifest(t) {
		if entry.Kind != "plain" && entry.Kind != "tiered-snapshot" {
			continue
		}
		t.Run(entry.Fixture, func(t *testing.T) {
			document, _, err := compatPlainDocument(compatRead(t, entry))
			if err != nil {
				t.Fatal(err)
			}
			table, err := decodeTable(document)
			if err != nil {
				t.Fatal(err)
			}
			forest, err := linkTable(table)
			if err != nil {
				t.Fatal(err)
			}
			added := core.NewNode(core.LeafNode, "unrelated")
			added.Parents = map[string]string{forest.ID: forest.Name}
			forest.Children[added.ID] = added
			rootID, before, beforeRaw := compatRecords(t, document)
			_, after, afterRaw := compatRecords(t, compatEncode(t, forest, table.LogSequence))
			if _, present := after[added.ID]; !present || len(after) != len(before)+1 {
				t.Fatalf("the unrelated node did not land beside the %d it joined", len(before))
			}
			for id, fields := range before {
				if id != rootID {
					if !bytes.Equal(beforeRaw[id], afterRaw[id]) {
						t.Errorf("node %s changed bytes", id)
					}
					continue
				}
				for key, value := range fields {
					if key != "children" && !bytes.Equal(value, after[id][key]) {
						t.Errorf("root key %q changed: %s -> %s", key, value, after[id][key])
					}
				}
			}
		})
	}
}

func compatBannerOf(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.SplitN(string(data), "\n", 2)[0]
}

// compatOpenFixture reads a fixture into a bare server the way a load does, level included, and
// installs the forest it holds.
func compatOpenFixture(t *testing.T, name string) *Server {
	t.Helper()
	server := compatBareServer(t, t.TempDir())
	path := filepath.Join(compatFixtureDir, name)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	table, err := server.readState(file)
	if err != nil {
		t.Fatal(err)
	}
	if server.forest, err = linkTable(table); err != nil {
		t.Fatal(err)
	}
	return server
}

func compatPersist(t *testing.T, server *Server) {
	t.Helper()
	if err := server.persistState(server.statePath()); err != nil {
		t.Fatal(err)
	}
}

// A store read at STATE-3 is written at STATE-3 after its last reference is gone (§7.8.5).
func TestStateThreeNeverDowngrades(t *testing.T) {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	server := compatOpenFixture(t, "plain-state3-acl-reference.ljstate")
	server.forest = &core.Node{ID: "plain", Name: "plain", Children: map[string]*core.Node{}}
	compatPersist(t, server)
	if banner := compatBannerOf(t, server.statePath()); banner != "LUMBERJACK-STATE-3" {
		t.Fatalf("a STATE-3 store with no reference left was written as %q", banner)
	}
}

// A STATE-2 store stays STATE-2 until a reference appears, and then stays STATE-3 (§7.8.5).
func TestStateTwoRisesOnlyWithAReference(t *testing.T) {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	server := compatOpenFixture(t, "plain-state2-all-fields.ljstate")
	compatPersist(t, server)
	if banner := compatBannerOf(t, server.statePath()); banner != "LUMBERJACK-STATE-2" {
		t.Fatalf("a STATE-2 store was written as %q", banner)
	}
	reference := core.NewNode(core.LeafNode, "reference")
	reference.Metadata = map[string]interface{}{"acl": map[string]interface{}{"contractRevision": compat.ACLReferenceRevision}}
	server.forest.Children[reference.ID] = reference
	compatPersist(t, server)
	if banner := compatBannerOf(t, server.statePath()); banner != "LUMBERJACK-STATE-3" {
		t.Fatalf("a store holding a reference was written as %q", banner)
	}
	delete(server.forest.Children, reference.ID)
	compatPersist(t, server)
	if banner := compatBannerOf(t, server.statePath()); banner != "LUMBERJACK-STATE-3" {
		t.Fatalf("removing the reference downgraded the store to %q", banner)
	}
}

// The mark the compatibility table carries is the one the STATE-3 fixture's references carry.
func TestCompatReferenceMarkIsTheStoredReferences(t *testing.T) {
	for _, entry := range compatManifest(t) {
		if entry.Fixture != "plain-state3-acl-reference" {
			continue
		}
		document, banner, err := compatPlainDocument(compatRead(t, entry))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(document, []byte(compat.ReferenceMark)) || banner != stateMagicReferences {
			t.Fatalf("the STATE-3 fixture does not carry %s", compat.ReferenceMark)
		}
		return
	}
	t.Fatal("the STATE-3 fixture is missing")
}

func compatEnvelopeVersion(t *testing.T, sealed []byte) int {
	t.Helper()
	var envelope encryptedStateEnvelope
	if err := json.Unmarshal(sealed, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Version
}

// Envelopes 5 and 6, sealed under the neutral label, are read; the level and label they carry are
// what the store keeps writing (§7.5).
func TestNeutralEnvelopesAreRead(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	forest := &core.Node{ID: "root", Name: "root", Children: map[string]*core.Node{}}
	child := &core.Node{ID: "child", Name: "child", Parents: map[string]string{"root": "root"},
		Metadata: map[string]interface{}{"price": json.Number("1.50")}}
	forest.Children[child.ID] = child
	for _, refs := range []bool{false, true} {
		if refs {
			child.Metadata["acl"] = map[string]interface{}{"contractRevision": compat.ACLReferenceRevision}
		}
		source, err := encodeState(forest)
		if err != nil {
			t.Fatal(err)
		}
		writer := &secureStorage{wrapper: &localStorageWrapper{key: key}, id: strings.Repeat("b", 64), accounts: map[string]storageAccountKey{}, label: compat.LabelNeutral}
		sealed, err := writer.encode(source)
		if err != nil {
			t.Fatal(err)
		}
		want := map[bool]int{false: 5, true: 6}[refs]
		if version := compatEnvelopeVersion(t, sealed); version != want {
			t.Fatalf("neutral envelope version %d, want %d", version, want)
		}
		reader := &secureStorage{wrapper: &localStorageWrapper{key: key}}
		opened, err := reader.decode(sealed)
		if err != nil {
			t.Fatalf("neutral envelope %d not read: %v", want, err)
		}
		if reader.label != compat.LabelNeutral || reader.level != map[bool]int{false: 2, true: 3}[refs] {
			t.Fatalf("envelope %d read as label %d level %d", want, reader.label, reader.level)
		}
		if !bytes.Contains(opened, []byte(`"price":1.50`)) {
			t.Fatalf("neutral envelope lost the literal: %s", opened)
		}
	}
}

// A sealed store reads flag-1 records under its version-1 key file and flag-2 records beside them,
// and a version-2 key file writes flag 2 (§7.8.8, read side; writes stay legacy for legacy stores).
func TestNeutralObjectRecordsAndKeyFileAreRead(t *testing.T) {
	key := compatUseFixtureKey(t)
	storage := &secureStorage{wrapper: &localStorageWrapper{key: key}, accounts: map[string]storageAccountKey{}}
	dir := filepath.Join(t.TempDir(), "store.objects")
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
	store, err := openObjectStore(dir, 1<<20, storage)
	if err != nil {
		t.Fatal(err)
	}
	if store.sealer.writeFlag != objectSealed {
		t.Fatalf("a version-1 key file writes flag %d", store.sealer.writeFlag)
	}
	store.sealer.writeFlag = objectSealedNeutral
	neutral := mustPut(t, store, []byte("a neutral record"))
	store.close()
	reopened := openTestStoreWith(t, dir, storage)
	mustGet(t, reopened, neutral.ID, []byte("a neutral record"))
	for _, body := range compatObjectBodies {
		mustGet(t, reopened, objectIDHex([]byte(body)), []byte(body))
	}
	compatNeutralKeyFile(t, storage)
}

func compatNeutralKeyFile(t *testing.T, storage *secureStorage) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "neutral.objects")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sealer, _ := objectSealerFor(compat.ObjectKeyFileNeutral, strings.Repeat("c", 64))
	master := bytes.Repeat([]byte{3}, 32)
	wrapped, err := storage.wrapper.Wrap(t.Context(), master, sealer.aad("master"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(objectKeyEnvelope{Version: compat.ObjectKeyFileNeutral, ID: sealer.id, Key: wrapped})
	if err := os.WriteFile(filepath.Join(dir, objectKeyFileName), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store := openTestStoreWith(t, dir, storage)
	if store.sealer.writeFlag != objectSealedNeutral || store.sealer.label != compat.LabelNeutral {
		t.Fatalf("a version-2 key file opened as label %d flag %d", store.sealer.label, store.sealer.writeFlag)
	}
	receipt := mustPut(t, store, []byte("under a neutral key file"))
	store.close()
	mustGet(t, openTestStoreWith(t, dir, storage), receipt.ID, []byte("under a neutral key file"))
}

func openTestStoreWith(t *testing.T, dir string, storage *secureStorage) *objectStore {
	t.Helper()
	store, err := openObjectStore(dir, 1<<20, storage)
	if err != nil {
		t.Fatalf("openObjectStore: %v", err)
	}
	t.Cleanup(store.close)
	return store
}

func objectIDHex(data []byte) string { return objectID(blake3.Sum256(data)).hex() }
