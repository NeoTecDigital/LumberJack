// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
)

// The outbox seam (docs/extension-api.md §4.6): Tx.Enqueue in the change's own snapshot, the Direct
// flag in place of product literals, the entitlement hook for records written before it, and
// presentation-only metadata.

type outboxInstance struct {
	host    extension.Host
	vouches map[string]bool // change id -> vouched
}

func (i *outboxInstance) Close(context.Context) error { return nil }

func (i *outboxInstance) EntitledLocked(_ extension.ReadTx, n core.OutboxNotification, _ string) bool {
	return i.vouches[n.Change.ID]
}

// outboxFixture is a stock server with a reader who can read one node, and an attached instance.
func outboxFixture(t *testing.T, spec extension.Spec) (*Server, *outboxInstance, *core.Node, string) {
	t.Helper()
	server, dir := newStockServer(t)
	_ = dir
	instance := &outboxInstance{vouches: map[string]bool{}}
	spec.Name = "outbox"
	ext := testExtension{spec: spec, attach: func(host extension.Host) (extension.Instance, error) {
		instance.host = host
		return instance, nil
	}}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
	reader := addLoginUser(t, server, "reader", nil)
	var node *core.Node
	if err := server.changeForest(func() error {
		node = core.NewNode(core.BranchNode, "shared-record")
		node.Parents = map[string]string{server.forest.ID: server.forest.Name}
		node.Users = []core.User{{ID: reader.ID, Permissions: []core.Permission{core.ReadPermission}}}
		node.Kind = "conversation"
		node.Metadata = map[string]interface{}{"assigned_to": reader.ID, "title": "Shared"}
		server.forest.Children[node.ID] = node
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return server, instance, node, reader.ID
}

// deliverTo places a pending change in a recipient's inbox, as the hub's deliver op does.
func deliverTo(t *testing.T, server *Server, userID string, change core.OutboxChange) {
	t.Helper()
	if err := server.changeForest(func() error {
		state := server.correspondenceState()
		state.Inbox[userID] = append(state.Inbox[userID], core.OutboxNotification{Change: change})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func notificationIDs(t *testing.T, server *Server, userID string) map[string]bool {
	t.Helper()
	bearer := sessionFor(t, server, userID, "reader")
	answer := server.ApplicationCall(ApplicationRequest{Method: "GET", Target: "/notifications", Headers: map[string]string{"Authorization": "Bearer " + bearer}})
	ids := map[string]bool{}
	for _, item := range decodeApplication(t, answer)["items"].([]interface{}) {
		ids[item.(map[string]interface{})["id"].(string)] = true
	}
	return ids
}

func TestEnqueueLandsWithItsChange(t *testing.T) {
	server, instance, node, reader := outboxFixture(t, extension.Spec{})
	if _, err := instance.host.Change(context.Background(), extension.WriteOp{Key: "notice"}, func(tx extension.Tx) error {
		return tx.Enqueue(core.OutboxChange{ID: "notice", PinID: node.ID, Path: "shared-record", Operation: "assign", Recipients: []string{reader}, Direct: true})
	}); err != nil {
		t.Fatal(err)
	}
	reloaded := reloadServer(t, server.config.Process.DatabasePath)
	change, held := reloaded.forest.Correspondence.Pending["notice"]
	if !held || !change.Direct || change.At == "" || len(change.Recipients) != 1 {
		t.Fatalf("the enqueued change did not land with its snapshot: %+v", change)
	}
	if _, err := instance.host.Change(context.Background(), extension.WriteOp{Key: "bad"}, func(tx extension.Tx) error {
		return tx.Enqueue(core.OutboxChange{ID: "no-pin"})
	}); err == nil {
		t.Fatal("an incomplete change was enqueued")
	}
}

// A Direct record reaches its reader; a record that is not Direct, not a share and not subscribed
// does not, whatever the node's kind or metadata say — the engine reads no product literal.
func TestDirectFlagReplacesProductLiterals(t *testing.T) {
	server, _, node, reader := outboxFixture(t, extension.Spec{})
	deliverTo(t, server, reader, core.OutboxChange{ID: "direct", PinID: node.ID, Path: "shared-record", Operation: "assign", Direct: true})
	deliverTo(t, server, reader, core.OutboxChange{ID: "legacy", PinID: node.ID, Path: "shared-record", Operation: "message"})
	deliverTo(t, server, reader, core.OutboxChange{ID: "share", PinID: node.ID, Path: "shared-record", Operation: "share"})
	ids := notificationIDs(t, server, reader)
	if !ids["direct"] || !ids["share"] || ids["legacy"] {
		t.Fatalf("notifications %v", ids)
	}
}

func TestLegacyRecordWithoutDirectNeedsSubscriptionOrVouch(t *testing.T) {
	server, instance, node, reader := outboxFixture(t, extension.Spec{})
	deliverTo(t, server, reader, core.OutboxChange{ID: "vouched", PinID: node.ID, Path: "shared-record", Operation: "message"})
	deliverTo(t, server, reader, core.OutboxChange{ID: "followed", PinID: node.ID, Path: "shared-record", Operation: "update"})
	if ids := notificationIDs(t, server, reader); len(ids) != 0 {
		t.Fatalf("records without Direct were shown unvouched and unsubscribed: %v", ids)
	}
	instance.vouches["vouched"] = true
	if ids := notificationIDs(t, server, reader); !ids["vouched"] || ids["followed"] {
		t.Fatalf("a vouched record: %v", ids)
	}
	if err := server.changeForest(func() error {
		server.subscribeLocked(node, reader, true)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if ids := notificationIDs(t, server, reader); !ids["vouched"] || !ids["followed"] {
		t.Fatalf("a subscriber's records: %v", ids)
	}
}

// A change to presentation-only metadata queues nothing for subscribers; any other change does.
func TestPresentationMetadataIsNotNews(t *testing.T) {
	server, _, node, reader := outboxFixture(t, extension.Spec{PresentationMetadata: []string{"layout"}})
	server.applicationHubEnabled.Store(true)
	if err := server.changeForest(func() error {
		server.subscribeLocked(node, reader, true)
		server.correspondenceState().Pending = map[string]core.OutboxChange{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	change := func(key string) int {
		if err := server.changeForest(func() error { node.Metadata[key] = key + "-changed"; return nil }); err != nil {
			t.Fatal(err)
		}
		return len(server.forest.Correspondence.Pending)
	}
	if queued := change("layout"); queued != 0 {
		t.Fatalf("a presentation-only change queued %d", queued)
	}
	if queued := change("title"); queued != 1 {
		t.Fatalf("a substantive change queued %d", queued)
	}
}
