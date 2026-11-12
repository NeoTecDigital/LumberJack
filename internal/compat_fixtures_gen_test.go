// Written by Richard Christopher, Copyright 2026 NeoTec, LLC

//go:build compatgen

package internal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// The compatibility fixtures are generated ONCE, at the cut, by the builders that existed then. They
// are what a store written by the cut build looks like, and every later step reads them back. Run
//
//	go test -tags compatgen -run TestGenerateCompatFixtures ./internal -count=1
//
// only at the cut commit: run anywhere later it would record the later build's bytes, which is the
// thing the fixtures exist to catch.

// compatFixtureKey is the local-test wrapping key the encrypted fixtures were written under. It is a
// disposable fixture key for the local-test mode, which no deployment can select by accident.
var compatFixtureKey = sha256.Sum256([]byte("lumberjack compat fixture local-test key"))

type compatGenerated struct {
	fixture  string
	kind     string
	contains string
	files    map[string]string // fixture file name -> source path
}

func TestGenerateCompatFixtures(t *testing.T) {
	out := compatFixtureDir
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	keyPath := filepath.Join(t.TempDir(), "local-test.key")
	if err := os.WriteFile(keyPath, compatFixtureKey[:], 0o600); err != nil {
		t.Fatal(err)
	}
	generated := []compatGenerated{
		compatGenAllFields(t),
		compatGenACLReference(t, false, keyPath),
		compatGenOwnedNumbers(t),
		compatGenPersonalBindings(t),
		compatGenEncryptedV3(t, keyPath),
		compatGenACLReference(t, true, keyPath),
		compatGenNested(t),
		compatGenTiered(t),
		compatGenObjects(t, keyPath),
	}
	var manifest bytes.Buffer
	keyEntry := compatManifestEntry{Fixture: "local-test-key", File: "local-test.key", Kind: "key",
		Contains: "the local-test wrapping key the enc-* and objects-* fixtures were sealed under"}
	compatCopy(t, keyPath, filepath.Join(out, keyEntry.File), &keyEntry)
	compatAppend(t, &manifest, keyEntry)
	for _, g := range generated {
		names := make([]string, 0, len(g.files))
		for name := range g.files {
			names = append(names, name)
		}
		sort.Strings(names)
		entries := make([]compatManifestEntry, 0, len(names))
		for _, name := range names {
			entry := compatManifestEntry{Fixture: g.fixture, File: name, Kind: g.kind, Contains: g.contains}
			if g.kind == "tiered-snapshot" && name != "tiered.ljstate" {
				entry.Kind = "tiered-log"
			}
			compatCopy(t, g.files[name], filepath.Join(out, name), &entry)
			entries = append(entries, entry)
		}
		for _, entry := range entries {
			if entry.Kind == "nested" || entry.Kind == "encrypted" || entry.Kind == "tiered-snapshot" {
				entry.LoadedSHA256 = compatSHA(compatLoadedDocument(t, entry, compatRead(t, entry)))
			}
			compatAppend(t, &manifest, entry)
		}
	}
	if err := os.WriteFile(filepath.Join(out, compatManifestName), manifest.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func compatCopy(t *testing.T, from, to string, entry *compatManifestEntry) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	entry.SHA256, entry.Bytes = compatHex(sum[:]), len(data)
	if entry.Kind == "plain" || entry.Kind == "tiered-snapshot" {
		document, banner, err := compatPlainDocument(data)
		if err != nil {
			t.Fatalf("%s: %v", entry.File, err)
		}
		docSum := sha256.Sum256(document)
		entry.DocumentSHA256, entry.Banner = compatHex(docSum[:]), strings.TrimSpace(strings.SplitN(banner, "\n", 2)[0])
		entry.ReencodeSHA256 = compatSHA(compatReencode(t, document))
	}
}

func compatAppend(t *testing.T, manifest *bytes.Buffer, entry compatManifestEntry) {
	t.Helper()
	line, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Write(append(line, '\n'))
}

// plain-state2-all-fields: every core.Node field, the outbox with feed, pending, inbox and outbound.
func compatGenAllFields(t *testing.T) compatGenerated {
	node := populatedNode(t)
	node.Correspondence = &core.Outbox{
		Feed:         &core.FeedState{Attempts: map[string][]core.FeedAttempt{"user-id": {{ID: "attempt", CommandID: "c", Digest: "d", Operation: "log", Outcome: "applied", Status: 200, At: "2026-03-04T05:06:07Z"}}}},
		Pending:      map[string]core.OutboxChange{"change": {ID: "change", Path: "populated", Actor: "user-id", Operation: "share", At: "2026-03-04T05:06:07Z", Recipients: []string{"user-id"}}},
		Inbox:        map[string][]core.OutboxNotification{"user-id": {{Change: core.OutboxChange{ID: "seen", Operation: "update"}}}},
		Delivered:    3,
		LastDelivery: "2026-03-04T05:06:07Z",
		Outbound:     map[string]core.OutboundMessage{"sms": {ID: "sms", Channel: "sms", Purpose: "mfa", To: "+15550100", Payload: "code", CreatedAt: 1, ExpiresAt: 2}},
	}
	node.Metadata["price"] = json.Number("1.50")
	server := stagedTestServer(t, t.TempDir())
	server.forest = node
	if err := server.persistState(server.statePath()); err != nil {
		t.Fatal(err)
	}
	return compatGenerated{"plain-state2-all-fields", "plain", "every core.Node field on the root, outbox feed/pending/inbox/outbound, metadata 1.50 restored by the root-ledger path",
		map[string]string{"plain-state2-all-fields.ljstate": server.statePath()}}
}

// plain-state3-acl-reference and enc-v4: an enrolled domain store holding an ACL reference.
func compatGenACLReference(t *testing.T, encrypted bool, keyPath string) compatGenerated {
	if encrypted {
		t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
		t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", keyPath)
		defer os.Setenv("CORRESPONDER_STORAGE_MODE", "")
	}
	f := newEnrollmentFixture(t)
	rootID := aclFixtureProvision(t, f, "compat-acl")
	aclSeedRecords(t, f, rootID, "copy", 2, aclFixtureCopy(t, f, rootID))
	aclSeedRecords(t, f, rootID, "follower", 1, aclFixtureFollower(rootID))
	if err := f.server.persistState(f.server.statePath()); err != nil {
		t.Fatal(err)
	}
	if encrypted {
		return compatGenerated{"enc-v4", "encrypted", "envelope version 4: an enrolled domain store holding an ACL reference, local-test key",
			map[string]string{"enc-v4.ljstate": f.server.statePath()}}
	}
	return compatGenerated{"plain-state3-acl-reference", "plain", "STATE-3 banner: an enrolled domain store holding an ACL reference",
		map[string]string{"plain-state3-acl-reference.ljstate": f.server.statePath()}}
}

// plain-owned-scope-numbers: an owned scope whose record carries exact numbers, with a pending
// command whose overlay reached the disk and whose acknowledgment was lost.
func compatGenOwnedNumbers(t *testing.T) compatGenerated {
	server := stagedTestServer(t, t.TempDir())
	record := server.forest.Children["account-root"].Children["data-root"].Children["record-a"]
	record.Metadata["big"] = json.Number("12345678901234567890")
	record.Metadata["price"] = json.Number("1.50")
	if err := server.configureStagedScope(stagedTestBinding(), stagedTestBounds()); err != nil {
		t.Fatal(err)
	}
	command := stagedTestCommand(t, server, "compat-pending")
	publish := server.stateWriter.write
	server.stateWriter.write = func(snapshot stateSnapshot) error {
		if err := publish(snapshot); err != nil {
			return err
		}
		return errors.New("compat fixture: acknowledgment lost after publish")
	}
	result, err := server.stageOwnedCommand(command, stagedTestAllow, stagedTestLabel("pending on disk"))
	if err == nil || result.Status != "unknown" {
		t.Fatalf("pending command = %#v, %v", result, err)
	}
	return compatGenerated{"plain-owned-scope-numbers", "plain", "owned scope marker, metadata 12345678901234567890 and 1.50, a pending command's overlay",
		map[string]string{"plain-owned-scope-numbers.ljstate": server.statePath()}}
}

// plain-personal-bindings: the root ledger that selects restoreAllNumbers.
func compatGenPersonalBindings(t *testing.T) compatGenerated {
	f := sourceUnitFixtureNew(t)
	sourceUnitCommitted(t, f)
	numbers := &core.Node{ID: "compat-numbers", Name: "numbers", Parents: map[string]string{f.server.forest.ID: f.server.forest.Name},
		Metadata: map[string]interface{}{"big": json.Number("12345678901234567890"), "price": json.Number("1.50")}}
	f.server.forest.Children[numbers.ID] = numbers
	if err := f.server.persistState(f.server.statePath()); err != nil {
		t.Fatal(err)
	}
	return compatGenerated{"plain-personal-bindings", "plain", "personal_bindings root ledger with a provisioned personal root; a node with 12345678901234567890 and 1.50",
		map[string]string{"plain-personal-bindings.ljstate": f.server.statePath()}}
}

// enc-v3: conversations with messages, accounts, a local-test key.
func compatGenEncryptedV3(t *testing.T, keyPath string) compatGenerated {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", keyPath)
	defer os.Setenv("CORRESPONDER_STORAGE_MODE", "")
	server, _ := newStockServer(t)
	defer server.Shutdown(context.Background())
	admin := adminID(t, server)
	server.forest.Users = append(server.forest.Users, core.User{ID: "reader", Username: "reader", Permissions: []core.Permission{core.ReadPermission}})
	leafFor(t, server, admin, "org/project/note")
	node, err := server.getNodeFromPath("org/project/note")
	if err != nil {
		t.Fatal(err)
	}
	node.Metadata = map[string]interface{}{"price": json.Number("1.50"), "label": "kept"}
	server.forest.Conversations = map[string]*core.Conversation{"dm": {ID: "dm", Kind: "dm",
		Members:  map[string]core.ConversationMember{admin: {From: 0}, "reader": {From: 1}},
		Messages: []core.ConversationMessage{{ID: "m1", Sequence: 1, Content: "first"}, {ID: "m2", Sequence: 2, Content: "second"}}}}
	if err := server.persistState(server.statePath()); err != nil {
		t.Fatal(err)
	}
	return compatGenerated{"enc-v3", "encrypted", "envelope version 3: two accounts, a conversation with two messages, metadata written as 1.50",
		map[string]string{"enc-v3.ljstate": server.statePath()}}
}

// nested-legacy: the pre-banner nested shape, diamond and all.
func compatGenNested(t *testing.T) compatGenerated {
	server, dir := newStockServer(t)
	defer server.Shutdown(context.Background())
	userID := adminID(t, server)
	diamond(t, server, userID)
	path := filepath.Join(dir, "nested.dat")
	writeNestedStateFile(t, path, server.forest)
	return compatGenerated{"nested-legacy", "nested", "pre-banner nested JSON with a diamond (one node under two parents)",
		map[string]string{"nested-legacy.ljstate": path}}
}

// tiered: a snapshot carrying log_sequence, and hot-log records past it.
func compatGenTiered(t *testing.T) compatGenerated {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	token := storeAdmin(t, server)
	for _, path := range []string{"tier/a", "tier/b"} {
		if code, body := storeCall(t, server, token, "POST", "/nodes", map[string]interface{}{"path": path, "type": "branch"}); code != 200 {
			t.Fatalf("create %s: %d %v", path, code, body)
		}
	}
	if _, err := server.snapshotCold(); err != nil {
		t.Fatal(err)
	}
	if code, body := storeCall(t, server, token, "POST", "/nodes", map[string]interface{}{"path": "tier/c", "type": "leaf"}); code != 200 {
		t.Fatalf("create tier/c: %d %v", code, body)
	}
	if code, body := storeCall(t, server, token, "PATCH", "/nodes/tier/a/metadata", json.RawMessage(`{"label":"after snapshot","n":2}`)); code != 200 {
		t.Fatalf("patch: %d %v", code, body)
	}
	abandon(server)
	statePath := StatePath(config)
	files := map[string]string{"tiered.ljstate": statePath}
	segments, err := filepath.Glob(statePath + ".log.*")
	if err != nil || len(segments) == 0 {
		t.Fatalf("no hot-log segments: %v", err)
	}
	for _, segment := range segments {
		files["tiered.ljstate"+strings.TrimPrefix(segment, statePath)] = segment
	}
	return compatGenerated{"tiered", "tiered-snapshot", "tiered snapshot with log_sequence plus hot-log records past it (kill, no final snapshot)", files}
}

// objects-sealed-v1: a key file at version 1 and a segment of flag-1 records.
func compatGenObjects(t *testing.T, keyPath string) compatGenerated {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	storage := &secureStorage{wrapper: &localStorageWrapper{key: key}, accounts: map[string]storageAccountKey{}}
	dir := filepath.Join(t.TempDir(), "store.objects")
	store, err := openObjectStore(dir, 1<<20, storage)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range compatObjectBodies {
		if _, err := store.put([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	store.close()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, entry := range entries {
		files["objects-sealed-v1.objects/"+entry.Name()] = filepath.Join(dir, entry.Name())
	}
	return compatGenerated{"objects-sealed-v1", "objects", "object key file version 1 and a segment of three flag-1 (sealed) records", files}
}
