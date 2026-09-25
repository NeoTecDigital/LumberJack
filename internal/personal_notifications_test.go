// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"testing"
)

func TestSharedReadDoesNotSubscribeToEveryEdit(t *testing.T) {
	// Proven red: read access silently subscribed Bob to ordinary edits.
	s := setupTestForest(t)
	s.forest.Users = append(s.forest.Users, core.User{ID: "bob", Username: "bob", Permissions: []core.Permission{core.ReadPermission}})
	result := workTestCommand(t, s, "admin", workCommand{Command: "create", Path: "root", ClientID: "project", Title: "Shared project", Kind: "project"}, 200)
	path := result["path"].(string)
	reviewedAccessGrant(t, s, "admin", path, "bob", 1, "item")
	s.forest.Correspondence.Pending = map[string]core.CorrespondenceChange{}
	workTestCommand(t, s, "admin", workCommand{Command: "log", Path: path, ClientID: "note", Content: "An ordinary edit"}, 200)
	for _, item := range s.forest.Correspondence.Pending {
		if len(item.Recipients) != 0 {
			t.Fatal("read access silently subscribed Bob to ordinary edits")
		}
	}
	workTestCommand(t, s, "bob", workCommand{Command: "subscribe", Path: path, ClientID: "follow", Subscribed: true}, 200)
	workTestCommand(t, s, "admin", workCommand{Command: "log", Path: path, ClientID: "subscribed-note", Content: "An update I asked for"}, 200)
	found := false
	for _, item := range s.forest.Correspondence.Pending {
		if item.Operation == "log" && len(item.Recipients) == 1 && item.Recipients[0] == "bob" {
			found = true
		}
	}
	if !found {
		t.Fatal("explicit subscription did not receive the update")
	}
}
