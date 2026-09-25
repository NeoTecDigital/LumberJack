// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// Evidence for the documented non-rollback boundary, not a claim of transaction
// isolation: a failed persist can leave content and staged inbox state in memory.
func TestAccessEncryptedFailureRecoveryKeepsStableCommandAndNotice(t *testing.T) {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", storageTestKey(t))
	s, _ := newStockServer(t)
	owner := adminID(t, s)
	s.forest.Users = append(s.forest.Users, core.User{ID: "reader", Username: "reader", Permissions: []core.Permission{core.ReadPermission}})
	path := workTestCommand(t, s, owner, workCommand{Command: "create", Path: s.forest.Name, ClientID: "private", Title: "Private", Kind: "idea"}, 200)["path"].(string)
	reviewedAccessGrant(t, s, owner, path, "reader", 0, "item")
	workTestCommand(t, s, "reader", workCommand{Command: "subscribe", Path: path, ClientID: "follow", Subscribed: true}, 200)
	if err := s.changeForest(func() error { s.correspondenceState().Pending = map[string]core.CorrespondenceChange{}; return nil }); err != nil {
		t.Fatal(err)
	}
	node, _ := s.getNodeFromPath(path)
	durableBefore, err := os.ReadFile(s.statePath())
	if err != nil {
		t.Fatal(err)
	}
	codec, err := s.storageCodec()
	if err != nil {
		t.Fatal(err)
	}
	original := codec.wrapper
	failing := &storageTestWrapper{localStorageWrapper: *original.(*localStorageWrapper), fail: true}
	codec.wrapper = failing
	cmd := workCommand{Command: "log", Path: path, ClientID: "retry-stable", Content: "Recover this entry once"}
	publishedBefore := len(publishedKinds(s))
	workTestCommand(t, s, owner, cmd, 500)
	if len(node.Entries) != 1 || len(s.correspondenceState().Pending) != 1 {
		t.Fatal("fixture did not exercise documented unacknowledged memory state")
	}
	entryID := node.Entries[0].ID
	var pendingID string
	for id := range s.correspondenceState().Pending {
		pendingID = id
	}
	after, err := os.ReadFile(s.statePath())
	if err != nil || !bytes.Equal(durableBefore, after) {
		t.Fatal("failed key service changed durable ciphertext")
	}
	if len(publishedKinds(s)) != publishedBefore {
		t.Fatal("failed command published a successful mutation")
	}
	// A fresh process reading the durable file cannot recover unacknowledged work.
	beforeRecovery, err := NewCore(s.config)
	if err != nil {
		t.Fatal(err)
	}
	restored, _ := beforeRecovery.getNodeFromPath(path)
	if len(restored.Entries) != 0 || len(beforeRecovery.correspondenceState().Pending) != 0 {
		t.Fatal("pre-recovery restart falsely retained failed work")
	}
	beforeRecovery.Shutdown(context.Background())
	// Hub delivery is another durable command. It also must return failure while
	// storage is down, though its staged inbox is visible in the trusted runtime.
	deliver, _ := json.Marshal(map[string]string{"operation": "deliver", "id": pendingID})
	if result, err := s.ApplicationHub(deliver); err == nil || result != nil {
		t.Fatal("hub acknowledged delivery before persistence")
	}
	if len(s.correspondenceState().Inbox["reader"]) != 1 {
		t.Fatal("expected documented staged inbox state")
	}
	after, _ = os.ReadFile(s.statePath())
	if !bytes.Equal(durableBefore, after) {
		t.Fatal("failed delivery changed durable state")
	}
	failing.fail = false
	ack := workTestCommand(t, s, owner, cmd, 200)
	if ack["result"].(map[string]interface{})["id"] != entryID || len(node.Entries) != 1 {
		t.Fatal("same client retry duplicated the mutation or changed receipt identity")
	}
	if len(s.correspondenceState().Inbox["reader"]) != 1 {
		t.Fatal("retry duplicated notification")
	}
	if _, err := s.ApplicationHub(deliver); err != nil {
		t.Fatal(err)
	}
	if len(s.correspondenceState().Inbox["reader"]) != 1 {
		t.Fatal("delivery retry duplicated notification")
	}
	recovered, err := NewCore(s.config)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Shutdown(context.Background())
	stable := workTestCommand(t, recovered, owner, cmd, 200)
	if stable["result"].(map[string]interface{})["id"] != entryID {
		t.Fatal("restart lost stable receipt")
	}
	reloaded, _ := recovered.getNodeFromPath(path)
	if len(reloaded.Entries) != 1 || len(recovered.correspondenceState().Inbox["reader"]) != 1 {
		t.Fatal("recovery did not durably keep exactly one entry and notification")
	}
}
