// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// The baseline has no secureStorage codec; the file-level regression's observed
// red is recorded in secure_storage_test.go. These exercise its trust boundaries.
type storageTestWrapper struct {
	localStorageWrapper
	fail  bool
	wraps int
}

func (w *storageTestWrapper) Wrap(ctx context.Context, key, aad []byte) (wrappedStorageKey, error) {
	if w.fail {
		return wrappedStorageKey{}, errors.New("key service unavailable")
	}
	w.wraps++
	return w.localStorageWrapper.Wrap(ctx, key, aad)
}

func TestStorageEnvelopesGrantHistoryAndTampering(t *testing.T) {
	// The exclusive-boundary fixture failed before the 2026-09-21 correction:
	// "message history/invitation key scope wrong". Sequence == From is private.
	wrapper := &storageTestWrapper{localStorageWrapper: localStorageWrapper{key: bytes.Repeat([]byte{9}, 32)}}
	codec := &secureStorage{wrapper: wrapper, id: string(bytes.Repeat([]byte{'a'}, 64)), accounts: map[string]storageAccountKey{}}
	forest := &core.Node{ID: "root", Name: "private security", Users: []core.User{{ID: "alice"}, {ID: "bob"}, {ID: "eve"}}, Children: map[string]*core.Node{}, Conversations: map[string]*core.Conversation{}}
	node := &core.Node{ID: "node", Name: "private attachment title", Users: []core.User{{ID: "alice", Permissions: []core.Permission{core.AdminPermission}}, {ID: "bob", Permissions: []core.Permission{core.ReadPermission}}}}
	forest.Children[node.ID] = node
	forest.Conversations["chat"] = &core.Conversation{ID: "chat", Members: map[string]core.ConversationMember{"alice": {From: 0}, "bob": {From: 1}, "eve": {Invited: true}}, Messages: []core.ConversationMessage{{ID: "one", Sequence: 1, Content: "old private message"}, {ID: "two", Sequence: 2, Content: "new private message"}}}
	source, err := encodeState(forest)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := codec.encode(source)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(node.Name)) || bytes.Contains(encoded, []byte("alice")) {
		t.Fatal("content or account metadata exposed outside envelope")
	}
	var outer encryptedStateEnvelope
	if err = json.Unmarshal(encoded, &outer); err != nil {
		t.Fatal(err)
	}
	master, err := wrapper.Unwrap(context.Background(), outer.Key, codec.aad("snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	zipped, err := storageOpen(master, outer.Payload, codec.aad("snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := readCappedGzip(bytes.NewReader(zipped), maxDecompressedState)
	if err != nil {
		t.Fatal(err)
	}
	var doc encryptedStateDocument
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Nodes["root"].AccountKeys) != 0 {
		t.Fatal("root security state wrapped to an account")
	}
	if len(doc.Nodes["node"].AccountKeys) != 2 {
		t.Fatal("resource key did not follow node grants")
	}
	if len(doc.Conversations["chat"].Messages["one"].AccountKeys) != 1 || len(doc.Conversations["chat"].Messages["two"].AccountKeys) != 2 {
		t.Fatal("message history/invitation key scope wrong")
	}
	restarted := &secureStorage{wrapper: wrapper}
	decoded, err := restarted.decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := decodeState(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Children["node"].Name != node.Name || len(recovered.Conversations["chat"].Messages) != 2 {
		t.Fatal("encrypted restart lost resource content")
	}
	node.Users = node.Users[:1]
	source, _ = encodeState(forest)
	encoded, err = codec.encode(source)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(encoded, &outer)
	master, _ = wrapper.Unwrap(context.Background(), outer.Key, codec.aad("snapshot"))
	zipped, _ = storageOpen(master, outer.Payload, codec.aad("snapshot"))
	raw, _ = readCappedGzip(bytes.NewReader(zipped), maxDecompressedState)
	doc = encryptedStateDocument{}
	_ = json.Unmarshal(raw, &doc)
	if len(doc.Nodes["node"].AccountKeys) != 1 {
		t.Fatal("revoked account retained resource wrap")
	}
	outer.Payload[len(outer.Payload)/2] ^= 1
	tampered, _ := json.Marshal(outer)
	if _, err = restarted.decode(tampered); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	// Moving ciphertext to a different resource identity cannot pass its AAD.
	if _, err = codec.openResource(master, "node/other", doc.Nodes["node"]); err == nil {
		t.Fatal("resource substitution accepted")
	}
}

func TestEncryptedStorageMigrationAndFailureAreAtomic(t *testing.T) {
	config := coreConfig()
	config.Process.DatabasePath = t.TempDir()
	s, err := NewCore(config)
	if err != nil {
		t.Fatal(err)
	}
	s.forest.Name = "retain original identity"
	id := s.forest.ID
	if err = s.persistState(s.statePath()); err != nil {
		t.Fatal(err)
	}
	s.Shutdown(context.Background())
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", storageTestKey(t))
	t.Setenv("CORRESPONDER_STORAGE_MIGRATE_LEGACY", "1")
	migrated, err := NewCore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Shutdown(context.Background())
	raw, err := os.ReadFile(migrated.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte(encryptedStateMagic)) || migrated.forest.ID != id {
		t.Fatal("migration did not encrypt before startup or preserve identity")
	}
	storage, _ := migrated.storageCodec()
	original := storage.wrapper
	key, _ := storageRandomKey()
	storage.wrapper = &storageTestWrapper{localStorageWrapper: localStorageWrapper{key: key}, fail: true}
	migrated.forest.Name = "unacknowledged mutation"
	if err = migrated.persistState(migrated.statePath()); err == nil {
		t.Fatal("key-service failure acknowledged")
	}
	after, err := os.ReadFile(migrated.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, after) {
		t.Fatal("failed key service changed durable ciphertext")
	}
	storage.wrapper = original
	t.Setenv("CORRESPONDER_STORAGE_MIGRATE_LEGACY", "0")
	t.Setenv("CORRESPONDER_STORAGE_REWRAP_KEYS", "1")
	rewrapped, err := NewCore(config)
	if err != nil {
		t.Fatal(err)
	}
	defer rewrapped.Shutdown(context.Background())
	if rewrapped.forest.Name != "retain original identity" {
		t.Fatal("rewrap changed durable content")
	}
	newBytes, _ := os.ReadFile(rewrapped.statePath())
	if bytes.Equal(raw, newBytes) {
		t.Fatal("rotation did not publish a fresh envelope")
	}
}
