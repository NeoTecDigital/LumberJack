// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func encryptedDocumentForTest(t *testing.T, codec *secureStorage, forest *core.Node) encryptedStateDocument {
	t.Helper()
	source, err := encodeState(forest)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := codec.encode(source)
	if err != nil {
		t.Fatal(err)
	}
	var envelope encryptedStateEnvelope
	if err = json.Unmarshal(sealed, &envelope); err != nil {
		t.Fatal(err)
	}
	key, err := codec.wrapper.Unwrap(context.Background(), envelope.Key, codec.aad("snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	zipped, err := storageOpen(key, envelope.Payload, codec.aad("snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := readCappedGzip(bytes.NewReader(zipped), maxDecompressedState)
	if err != nil {
		t.Fatal(err)
	}
	var document encryptedStateDocument
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestAccessWallClockExpiryDeniesReadsWritesWrapsAndStream(t *testing.T) {
	s, owner, base := streamingServer(t)
	s.forest.Users = append(s.forest.Users, core.User{ID: "reader", Username: "reader", Permissions: []core.Permission{core.ReadPermission}})
	path := workTestCommand(t, s, owner, workCommand{Command: "create", Path: s.forest.Name, ClientID: "expiring", Title: "Private after expiry", Kind: "idea"}, 200)["path"].(string)
	node, _ := s.getNodeFromPath(path)
	expires := time.Now().Unix() + 2
	request := map[string]interface{}{"action": "grant", "path": path, "username": "reader", "permission": 1, "scope": "item", "expires_at": expires}
	preview := accessTestCall(t, s, owner, "/access/preview", request, 200)
	request["revision"] = preview["revision"]
	accessTestCall(t, s, owner, "/access/apply", request, 200)
	// Explicit conversation membership is a separate authority. Expiring project
	// access must not silently remove a member from an independently shared chat.
	s.forest.Conversations = map[string]*core.Conversation{"independent": {ID: "independent", Members: map[string]core.ConversationMember{owner: {From: 0}, "reader": {From: 0}}, Messages: []core.ConversationMessage{{ID: "message", Sequence: 1, Content: "Explicitly shared chat"}}}}
	codec := &secureStorage{wrapper: &localStorageWrapper{key: bytes.Repeat([]byte{7}, 32)}, id: string(bytes.Repeat([]byte{'a'}, 64)), accounts: map[string]storageAccountKey{}}
	before := encryptedDocumentForTest(t, codec, s.forest)
	if len(before.Nodes[node.ID].AccountKeys["reader"]) == 0 {
		t.Fatal("unexpired recipient missing its resource wrap")
	}
	reader := openStream(t, base, "reader", "")
	defer reader.close()
	waitForSubscriber(t, s)
	time.Sleep(time.Until(time.Unix(expires, 0)) + 25*time.Millisecond)
	// No mutation or materialization refresh has occurred at the wall-clock boundary.
	if response := serveRoute(t, s, "GET", "/nodes/"+path, "reader", nil); response.Code != 403 {
		t.Fatalf("expired read returned %d: %s", response.Code, response.Body.String())
	}
	workTestCommand(t, s, "reader", workCommand{Command: "log", Path: path, ClientID: "expired-write", Content: "Denied"}, 403)
	workspace, err := s.Workspace("reader")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(workspace, []byte("Private after expiry")) {
		t.Fatal("expired workspace revealed content")
	}
	after := encryptedDocumentForTest(t, codec, s.forest)
	if len(after.Nodes[node.ID].AccountKeys["reader"]) != 0 {
		t.Fatal("expired grant retained a newly persisted resource wrap")
	}
	if len(after.Conversations["independent"].Messages["message"].AccountKeys["reader"]) == 0 {
		t.Fatal("project expiry incorrectly revoked independent conversation membership")
	}
	workTestCommand(t, s, owner, workCommand{Command: "log", Path: path, ClientID: "private-now", Content: "Protected after expiry"}, 200)
	deadline := time.After(time.Second)
	resync := false
	for !resync {
		select {
		case line := <-reader.lines:
			if line == "event: mutation" {
				t.Fatal("expired recipient received protected stream mutation")
			}
			if line == "event: resync" {
				resync = true
			}
		case <-deadline:
			t.Fatal("next protected change did not request resynchronization")
		}
	}
	// Consume the empty resync body, then prove subsequent content stays silent.
	for line := range reader.lines {
		if line == "data: {}" {
			break
		}
	}
	workTestCommand(t, s, owner, workCommand{Command: "log", Path: path, ClientID: "still-private", Content: "Still protected"}, 200)
	reader.silentFor(t, 50*time.Millisecond)
}
