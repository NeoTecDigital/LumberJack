// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func accessTestCall(t *testing.T, s *Server, user, route string, request interface{}, status int) map[string]interface{} {
	t.Helper()
	raw, _ := json.Marshal(request)
	rec := httptest.NewRecorder()
	s.handleAccess(rec, withUser(httptest.NewRequest("POST", route, bytes.NewReader(raw)), user))
	if rec.Code != status {
		t.Fatalf("%s: got %d want %d: %s", route, rec.Code, status, rec.Body.String())
	}
	var result map[string]interface{}
	if status == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func reviewedAccessGrant(t *testing.T, s *Server, actor, path, username string, permission int, scope string) string {
	t.Helper()
	request := map[string]interface{}{"action": "grant", "path": path, "username": username, "permission": permission, "scope": scope}
	preview := accessTestCall(t, s, actor, "/access/preview", request, 200)
	request["revision"] = preview["revision"]
	return accessTestCall(t, s, actor, "/access/apply", request, 200)["grant_id"].(string)
}

func reviewedAccessRevoke(t *testing.T, s *Server, actor, path, grantID string) {
	t.Helper()
	request := map[string]interface{}{"action": "revoke", "path": path, "grant_id": grantID}
	preview := accessTestCall(t, s, actor, "/access/preview", request, 200)
	request["revision"] = preview["revision"]
	accessTestCall(t, s, actor, "/access/apply", request, 200)
}

func accessAuthorityFixture(t *testing.T) (*Server, string) {
	t.Helper()
	s := setupTestForest(t)
	for _, id := range []string{"manager", "reader", "editor"} {
		s.forest.Users = append(s.forest.Users, core.User{ID: id, Username: id, Permissions: []core.Permission{core.ReadPermission}})
	}
	path := workTestCommand(t, s, "admin", workCommand{Command: "create", Path: "root", ClientID: "owned", Title: "Owned", Kind: "project"}, 200)["path"].(string)
	reviewedAccessGrant(t, s, "admin", path, "manager", 2, "item")
	return s, path
}

// Observed red 2026-09-21: legacy share/shared creation returned 200; editor unlink
// returned 200 and owner downgrade preview returned 200.
func TestAccessLegacyAudienceMutationsRetired(t *testing.T) {
	for _, permission := range []int{-1, 0, 1} {
		t.Run(string(rune('2'+permission)), func(t *testing.T) {
			s, path := accessAuthorityFixture(t)
			workTestCommand(t, s, "manager", workCommand{Command: "share", Path: path, ClientID: "attack", Username: "admin", Permission: &permission}, 410)
			node, _ := s.getNodeFromPath(path)
			if !node.CheckPermission("admin", core.AdminPermission) {
				t.Fatal("owner lost access")
			}
			request := map[string]interface{}{"path": path, "assignee_id": "admin", "permission": permission}
			rec := post(t, s.handleAssignUser, "manager", request)
			if rec.Code != 410 {
				t.Fatalf("legacy assign returned %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
	t.Run("shared creation", func(t *testing.T) {
		s, path := accessAuthorityFixture(t)
		node, _ := s.getNodeFromPath(path)
		before := len(node.Children)
		workTestCommand(t, s, "admin", workCommand{Command: "create", Path: path, ClientID: "unsafe", Title: "Unsafe", Kind: "idea", Shared: true}, 410)
		if len(node.Children) != before {
			t.Fatal("retired shared creation mutated children")
		}
		privatePath := workTestCommand(t, s, "admin", workCommand{Command: "create", Path: path, ClientID: "private", Title: "Private", Kind: "idea"}, 200)["path"].(string)
		private, _ := s.getNodeFromPath(privatePath)
		if private.CheckPermission("manager", core.ReadPermission) {
			t.Fatal("private create inherited audience")
		}
	})
	t.Run("legacy chat", func(t *testing.T) {
		s, path := accessAuthorityFixture(t)
		workTestCommand(t, s, "admin", workCommand{Command: "chat", Path: path, ClientID: "chat", Username: "reader"}, 410)
	})
}

func TestAccessOwnerCannotBeDowngradedAndStaleReviewFails(t *testing.T) {
	s, path := accessAuthorityFixture(t)
	for _, permission := range []int{0, 1} {
		accessTestCall(t, s, "manager", "/access/preview", map[string]interface{}{"action": "grant", "path": path, "username": "admin", "permission": permission, "scope": "item"}, 409)
	}
	node, _ := s.getNodeFromPath(path)
	accessTestCall(t, s, "manager", "/access/preview", map[string]interface{}{"action": "revoke", "path": path, "grant_id": "direct:" + node.ID + ":admin"}, 409)
	request := map[string]interface{}{"action": "grant", "path": path, "username": "reader", "permission": 0, "scope": "item"}
	preview := accessTestCall(t, s, "admin", "/access/preview", request, 200)
	reviewedAccessGrant(t, s, "admin", path, "editor", 1, "item")
	request["revision"] = preview["revision"]
	accessTestCall(t, s, "admin", "/access/apply", request, 409)
	if node.CheckPermission("reader", core.ReadPermission) {
		t.Fatal("stale apply changed audience")
	}
	// Legacy data cannot erase the creator's authority by omitting its Users row.
	node.Users = nil
	if !node.CheckPermission("admin", core.AdminPermission) {
		t.Fatal("creator no longer has owner authority")
	}
}

func unlinkAuthorityFixture(t *testing.T) (*Server, string, string, string) {
	t.Helper()
	s, parent := accessAuthorityFixture(t)
	other := workTestCommand(t, s, "admin", workCommand{Command: "create", Path: "root", ClientID: "other", Title: "Other", Kind: "project"}, 200)["path"].(string)
	child := workTestCommand(t, s, "admin", workCommand{Command: "create", Path: other, ClientID: "child", Title: "Child", Kind: "idea"}, 200)["path"].(string)
	reviewedAccessGrant(t, s, "admin", parent, "reader", 1, "ongoing")
	reviewedAccessGrant(t, s, "admin", parent, "editor", 1, "item")
	reviewedAccessGrant(t, s, "admin", child, "editor", 1, "item")
	request := map[string]interface{}{"action": "link", "parent_path": parent, "child_path": child}
	preview := accessTestCall(t, s, "admin", "/access/preview", request, 200)
	request["sharing_revision"] = preview["revision"]
	rec := serveRoute(t, s, "POST", "/nodes/link", "admin", request)
	if rec.Code != 200 {
		t.Fatalf("reviewed link failed %d: %s", rec.Code, rec.Body.String())
	}
	return s, parent, other, child
}

func TestAccessUnlinkRequiresReviewAndPreservesIndependentGrant(t *testing.T) {
	s, parent, other, child := unlinkAuthorityFixture(t)
	request := map[string]interface{}{"action": "unlink", "parent_path": parent, "child_path": child}
	denied := serveRoute(t, s, "DELETE", "/nodes/link", "editor", request)
	if denied.Code != 403 {
		t.Fatalf("editor revoked audience: got %d: %s", denied.Code, denied.Body.String())
	}
	accessTestCall(t, s, "editor", "/access/preview", request, 403)
	preview := accessTestCall(t, s, "admin", "/access/preview", request, 200)
	if preview["action"] != "unlink" || len(preview["items"].([]interface{})) != 1 {
		t.Fatalf("wrong unlink preview: %#v", preview)
	}
	item := preview["items"].([]interface{})[0].(map[string]interface{})
	if item["after_permission"] != float64(-1) {
		t.Fatalf("not a revocation: %#v", item)
	}
	request["sharing_revision"] = preview["revision"]
	independent := reviewedAccessGrant(t, s, "admin", child, "reader", 0, "item")
	stale := serveRoute(t, s, "DELETE", "/nodes/link", "admin", request)
	if stale.Code != 409 {
		t.Fatalf("stale unlink got %d: %s", stale.Code, stale.Body.String())
	}
	delete(request, "sharing_revision")
	preview = accessTestCall(t, s, "admin", "/access/preview", request, 200)
	item = preview["items"].([]interface{})[0].(map[string]interface{})
	if item["current_permission"] != float64(1) || item["after_permission"] != float64(0) {
		t.Fatalf("independent grant omitted: %#v", item)
	}
	found := false
	for _, raw := range item["sources"].([]interface{}) {
		if raw.(map[string]interface{})["id"] == independent {
			found = true
		}
	}
	if !found {
		t.Fatal("preview omitted remaining independent source")
	}
	request["sharing_revision"] = preview["revision"]
	accepted := serveRoute(t, s, "DELETE", "/nodes/link", "admin", request)
	if accepted.Code != 200 {
		t.Fatalf("reviewed unlink failed %d: %s", accepted.Code, accepted.Body.String())
	}
	node, _ := s.getNodeFromPath(child)
	if !node.CheckPermission("reader", core.ReadPermission) || node.CheckPermission("reader", core.WritePermission) {
		t.Fatal("unlink did not remove only ongoing source")
	}
	if len(node.Parents) != 1 || !strings.HasPrefix(child, other+"/") {
		t.Fatal("independent parent was lost")
	}
	if _, err := s.getNodeFromPath(parent + "/" + node.Name); err == nil {
		t.Fatal("unlinked parent still resolves child")
	}
	if kinds := publishedKinds(s); kinds[len(kinds)-1] != mutationNodeUnlinked {
		t.Fatalf("unlink failed to publish resynchronization: %v", kinds)
	}
}

func TestAccessTopologyWithoutAudienceChangeNeedsOnlyEdit(t *testing.T) {
	s, parent := accessAuthorityFixture(t)
	child := workTestCommand(t, s, "admin", workCommand{Command: "create", Path: "root", ClientID: "editable", Title: "Editable", Kind: "idea"}, 200)["path"].(string)
	for _, path := range []string{parent, child} {
		reviewedAccessGrant(t, s, "admin", path, "editor", 1, "item")
	}
	request := map[string]interface{}{"parent_path": parent, "child_path": child}
	for _, method := range []string{"POST", "DELETE"} {
		rec := serveRoute(t, s, method, "/nodes/link", "editor", request)
		if rec.Code != 200 {
			t.Fatalf("ordinary %s got %d: %s", method, rec.Code, rec.Body.String())
		}
	}
}

func TestAccessReviewedUnlinkResynchronizesRevokedReader(t *testing.T) {
	s, parent, _, child := unlinkAuthorityFixture(t)
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleStream(w, withUser(r, r.Header.Get("X-Test-User")))
	}))
	defer listener.Close()
	reader := openStream(t, listener.URL, "reader", "")
	defer reader.close()
	waitForSubscriber(t, s)
	request := map[string]interface{}{"action": "unlink", "parent_path": parent, "child_path": child}
	preview := accessTestCall(t, s, "admin", "/access/preview", request, 200)
	request["sharing_revision"] = preview["revision"]
	if rec := serveRoute(t, s, "DELETE", "/nodes/link", "admin", request); rec.Code != 200 {
		t.Fatalf("unlink failed %d: %s", rec.Code, rec.Body.String())
	}
	deadline := time.After(time.Second)
	for {
		select {
		case line := <-reader.lines:
			if line == "event: mutation" {
				t.Fatal("revoked reader received private topology")
			}
			if line == "event: resync" {
				return
			}
		case <-deadline:
			t.Fatal("reviewed unlink failed to resynchronize revoked reader")
		}
	}
}
