package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
)

// newStockServer is a server as a fresh install has one: a forest with an admin user and nothing
// else, in a directory of its own.
func newStockServer(t *testing.T) (*Server, string) {
	t.Helper()

	dir := t.TempDir()
	config := types.ServerConfig{
		Organization: "test_org",
		Process: types.ProcessInfo{
			ID:           "stock_process",
			Name:         "stock",
			ServerURL:    "localhost",
			ServerPort:   "8080",
			LogPath:      dir,
			DatabasePath: dir,
		},
	}

	server, err := NewServer(config, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	return server, dir
}

// adminID is the id of the user a fresh install made, which is the only user that can do anything.
func adminID(t *testing.T, server *Server) string {
	t.Helper()

	if len(server.forest.Users) != 1 {
		t.Fatalf("Expected exactly one user on a fresh forest, got %d", len(server.forest.Users))
	}
	return server.forest.Users[0].ID
}

// post calls a handler the way authMiddleware would: with the user id in the request context.
func post(t *testing.T, handler http.HandlerFunc, userID string, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Failed to encode request: %v", err)
	}

	request := httptest.NewRequest("POST", "/", bytes.NewBuffer(encoded))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), "user_id", userID))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// The whole documented event flow, over the handlers, on an instance nobody has repaired by hand.
// Every step of this answered 500 before: the admin had no write permission, and the only node
// that existed was the root branch, which no event can be started on.
func TestEventFlowOnAStockInstance(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	path := "work/projects/project-alpha"

	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": path,
		"type": "leaf",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}

	steps := []struct {
		name    string
		handler http.HandlerFunc
		body    map[string]interface{}
	}{
		{"start", server.handleStartEvent, map[string]interface{}{
			"path": path, "event_id": "sprint-1", "metadata": map[string]interface{}{"type": "sprint"},
		}},
		{"append", server.handleAppendToEvent, map[string]interface{}{
			"path": path, "event_id": "sprint-1", "content": "shipped", "metadata": map[string]interface{}{},
		}},
		{"end", server.handleEndEvent, map[string]interface{}{
			"path": path, "event_id": "sprint-1",
		}},
	}

	for _, step := range steps {
		recorder := post(t, step.handler, userID, step.body)
		if recorder.Code != http.StatusOK {
			t.Fatalf("Event %s: got %d, want %d: %s", step.name, recorder.Code, http.StatusOK, recorder.Body.String())
		}
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the node the event was tracked on: %v", err)
	}
	if entries := node.Events["sprint-1"].Entries; len(entries) != 1 {
		t.Fatalf("Expected 1 entry on the event, got %d", len(entries))
	}

	// The state landed in the database's own directory and NOT in the working directory, which is
	// where the relative "state_file.dat" used to put it.
	if _, err := os.Stat(filepath.Join(dir, "stock.dat")); err != nil {
		t.Errorf("Expected the state file in the database directory: %v", err)
	}
	if _, err := os.Stat("state_file.dat"); !os.IsNotExist(err) {
		t.Errorf("A state file was written to the working directory")
	}
}

// Intermediate segments are branches whatever was asked for, since they hold a child.
func TestCreateNodeMakesAncestorsBranches(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": "work/projects/project-alpha",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}

	for path, want := range map[string]core.NodeType{
		"work":                        core.BranchNode,
		"work/projects":               core.BranchNode,
		"work/projects/project-alpha": core.LeafNode,
	} {
		node, err := server.getNodeFromPath(path)
		if err != nil {
			t.Fatalf("Failed to find %s: %v", path, err)
		}
		if node.Type != want {
			t.Errorf("%s: got type %d, want %d", path, node.Type, want)
		}
	}
}

// Creating the same path twice is the same node, not two nodes of the same name — only one of
// which a path lookup could ever reach.
func TestCreateNodeIsIdempotent(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	body := map[string]interface{}{"path": "work", "type": "leaf"}

	first := post(t, server.handleCreateNode, userID, body)
	second := post(t, server.handleCreateNode, userID, body)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("Create node twice: got %d and %d, want %d", first.Code, second.Code, http.StatusOK)
	}
	if len(server.forest.Children) != 1 {
		t.Fatalf("Expected 1 child on the root, got %d", len(server.forest.Children))
	}

	// The same name with a different type is a conflict rather than a silent second node.
	conflict := post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "work", "type": "branch"})
	if conflict.Code != http.StatusConflict {
		t.Errorf("Create node with a conflicting type: got %d, want %d", conflict.Code, http.StatusConflict)
	}
}

// A user with no permission on the forest cannot grow it.
func TestCreateNodeRefusesWithoutWritePermission(t *testing.T) {
	server, _ := newStockServer(t)

	recorder := post(t, server.handleCreateNode, "someone-else", map[string]interface{}{"path": "work"})
	if recorder.Code != http.StatusForbidden {
		t.Errorf("Create node as a stranger: got %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

// Admin implies write. The admin user a fresh install creates holds AdminPermission and every
// event route asks for WritePermission, which used to be an exact match and so refused.
func TestAdminPermissionImpliesWrite(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	if !server.forest.CheckPermission(userID, core.WritePermission) {
		t.Error("Admin should imply write")
	}
	if !server.forest.CheckPermission(userID, core.ReadPermission) {
		t.Error("Admin should imply read")
	}

	reader := core.User{ID: "reader"}
	if err := server.forest.AssignUser(reader, core.ReadPermission); err != nil {
		t.Fatalf("Failed to assign the reader: %v", err)
	}
	if server.forest.CheckPermission("reader", core.WritePermission) {
		t.Error("Read should not imply write")
	}
}

// A node created on one run is reachable on the next, and the routes that read it do not panic.
// A loaded database used to come up with no cache at all, so every node-path route nil-panicked
// in getFromCache and a restart was fatal to the whole event surface.
func TestLoadedServerServesNodePaths(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)

	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "work"}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}

	loaded, err := LoadServer(types.ServerConfig{
		Process: types.ProcessInfo{
			ID:           "stock_process",
			Name:         "stock",
			LogPath:      dir,
			DatabasePath: dir,
		},
	})
	if err != nil {
		t.Fatalf("Failed to load the database: %v", err)
	}

	if loaded.cache == nil {
		t.Fatal("A loaded server has no cache")
	}
	if loaded.apiQueue == nil {
		t.Fatal("A loaded server has no api queue")
	}

	node, err := loaded.getNodeFromPath("work")
	if err != nil {
		t.Fatalf("Failed to find the node in the loaded forest: %v", err)
	}
	if node.Name != "work" {
		t.Errorf("Loaded the wrong node: %s", node.Name)
	}

	// The event flow works on the loaded database too, which is the whole point of loading one.
	if code := post(t, loaded.handleStartEvent, userID, map[string]interface{}{
		"path": "work", "event_id": "after-restart", "metadata": map[string]interface{}{},
	}).Code; code != http.StatusOK {
		t.Errorf("Start event on a loaded database: got %d, want %d", code, http.StatusOK)
	}
}
