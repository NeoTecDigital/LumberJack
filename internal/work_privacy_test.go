// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"testing"
)

func TestPrivateCaptureUnderSharedProject(t *testing.T) {
	s := setupTestForest(t)
	s.forest.Users = append(s.forest.Users, core.User{ID: "bob", Username: "bob", Permissions: []core.Permission{core.ReadPermission}})
	parent := workTestCommand(t, s, "admin", workCommand{Command: "create", Path: "root", ClientID: "parent", Title: "Shared project", Kind: "project"}, 200)["path"].(string)
	reviewedAccessGrant(t, s, "admin", parent, "bob", 1, "item")
	child := workTestCommand(t, s, "admin", workCommand{Command: "create", Path: parent, ClientID: "private", Title: "Private", Kind: "idea"}, 200)["path"].(string)
	node, _ := s.getNodeFromPath(child)
	if node.CheckPermission("bob", core.ReadPermission) {
		t.Fatal("private capture inherited direct parent audience")
	}
	reviewedAccessGrant(t, s, "admin", child, "bob", 1, "item")
	if !node.CheckPermission("bob", core.WritePermission) {
		t.Fatal("reviewed sharing did not grant edit access")
	}
}
