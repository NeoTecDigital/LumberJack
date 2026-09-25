// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// Baseline POST /access/preview returned 404 (parent's observed red). These
// adversarial cases hold the authority boundaries of the resulting interface.
func TestAccessLinkPreviewAndStaleRevision(t *testing.T) {
	s := setupTestForest(t)
	s.forest.Users = append(s.forest.Users, core.User{ID: "bob", Username: "bob", Permissions: []core.Permission{core.ReadPermission}})
	token, _, err := s.mintApplicationSession("admin")
	if err != nil {
		t.Fatal(err)
	}
	create := func(path, title string) string {
		return workTestCommand(t, s, "admin", workCommand{Command: "create", Path: path, Title: title, ClientID: title, Kind: "idea"}, 200)["path"].(string)
	}
	shared := create("root", "shared")
	private := create("root", "private")
	leaf := create(private, "leaf")
	grant := map[string]interface{}{"action": "grant", "path": shared, "username": "bob", "scope": "ongoing", "permission": 0}
	preview := conversationCall(t, s, token, "POST", "/access/preview", grant, 200)
	grant["revision"] = preview["revision"]
	conversationCall(t, s, token, "POST", "/access/apply", grant, 200)
	link := map[string]interface{}{"parent_path": shared, "child_path": private}
	conversationCall(t, s, token, "POST", "/nodes/link", link, 409)
	parent, _ := s.getNodeFromPath(shared)
	child, _ := s.getNodeFromPath(private)
	nested, _ := s.getNodeFromPath(leaf)
	if parent.Children[child.ID] != nil || child.CheckPermission("bob", core.ReadPermission) {
		t.Fatal("failed link changed topology or audience")
	}
	request := map[string]interface{}{"action": "link", "parent_path": shared, "child_path": private}
	preview = conversationCall(t, s, token, "POST", "/access/preview", request, 200)
	if len(preview["items"].([]interface{})) != 2 {
		t.Fatal("link preview omitted descendant")
	}
	link["sharing_revision"] = preview["revision"]
	create(private, "late-child")
	conversationCall(t, s, token, "POST", "/nodes/link", link, 409)
	preview = conversationCall(t, s, token, "POST", "/access/preview", request, 200)
	link["sharing_revision"] = preview["revision"]
	if result := post(t, s.handleLinkNode, "admin", link); result.Code != 200 {
		t.Fatalf("confirmed link: %d %s", result.Code, result.Body.String())
	}
	if !child.CheckPermission("bob", core.ReadPermission) || !nested.CheckPermission("bob", core.ReadPermission) {
		t.Fatal("confirmed link did not apply ongoing branch")
	}
}

func TestAccessRefusesUnauthorizedDescendantAndExpires(t *testing.T) {
	s := setupTestForest(t)
	s.forest.Users = append(s.forest.Users, core.User{ID: "bob", Username: "bob", Permissions: []core.Permission{core.ReadPermission}})
	token, _, err := s.mintApplicationSession("admin")
	if err != nil {
		t.Fatal(err)
	}
	branch := workTestCommand(t, s, "admin", workCommand{Command: "create", Path: "root", Title: "branch", ClientID: "branch", Kind: "idea"}, 200)["path"].(string)
	nested := workTestCommand(t, s, "admin", workCommand{Command: "create", Path: branch, Title: "nested", ClientID: "nested", Kind: "idea"}, 200)["path"].(string)
	child, _ := s.getNodeFromPath(nested)
	child.CreatedBy = "bob" // This fixture is owned by Bob, not the requesting administrator.
	child.Users = []core.User{{ID: "bob", Permissions: []core.Permission{core.AdminPermission}}, {ID: "admin", Permissions: []core.Permission{core.ReadPermission}}}
	request := map[string]interface{}{"action": "grant", "path": branch, "username": "bob", "scope": "ongoing", "permission": 0}
	conversationCall(t, s, token, "POST", "/access/preview", request, 403)
	node, _ := s.getNodeFromPath(branch)
	if node.CheckPermission("bob", core.ReadPermission) {
		t.Fatal("unauthorized branch preview granted partial rights")
	}
	request["scope"] = "item"
	request["expires_at"] = time.Now().Unix() + 100
	preview := conversationCall(t, s, token, "POST", "/access/preview", request, 200)
	request["revision"] = preview["revision"]
	applied := conversationCall(t, s, token, "POST", "/access/apply", request, 200)
	id := applied["grant_id"].(string)
	policy := s.forest.AccessPolicies[id]
	policy.ExpiresAt = time.Now().Unix() - 1
	s.forest.AccessPolicies[id] = policy
	s.refreshAccessGrantsLocked()
	if node.CheckPermission("bob", core.ReadPermission) {
		t.Fatal("expired grant retained access")
	}
	request["path"] = "root"
	conversationCall(t, s, token, "POST", "/access/preview", request, 400)
}

func TestAccessViewerCannotMutateOrRemoveOwner(t *testing.T) {
	s := setupTestForest(t)
	s.forest.Users = append(s.forest.Users, core.User{ID: "bob", Username: "bob", Permissions: []core.Permission{core.ReadPermission}})
	node := s.forest.Children["test-node"]
	node.AssignUser(core.User{ID: "bob"}, core.ReadPermission)
	token, _, err := s.mintApplicationSession("bob")
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]interface{}{"action": "grant", "path": "root/test-node", "username": "bob", "scope": "item", "permission": 2}
	conversationCall(t, s, token, "POST", "/access/preview", request, 403)
	admin, _, err := s.mintApplicationSession("admin")
	if err != nil {
		t.Fatal(err)
	}
	conversationCall(t, s, admin, "POST", "/access/preview", map[string]interface{}{"action": "revoke", "path": "root/test-node", "grant_id": "direct:test-node:admin"}, 409)
	recorder := httptest.NewRecorder()
	s.handleAccess(recorder, withUser(httptest.NewRequest(http.MethodGet, "/access?path=root/test-node", nil), "bob"))
	if recorder.Code != 200 {
		t.Fatal("authorized sharing summary unavailable")
	}
}
