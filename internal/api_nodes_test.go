package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// A leaf that records nothing is promoted to a branch when a child is added beneath it.
//
// POST /nodes could not nest under a path it had itself created: the first call made a leaf, and
// the second answered 409 forever. A leaf is only a leaf because nothing has been put beneath it.
func TestCreateNodePromotesAnEmptyLeaf(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": "work", "type": "leaf",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create the leaf: got %d, want %d", code, http.StatusOK)
	}

	nested := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": "work/task", "type": "leaf",
	})
	if nested.Code != http.StatusOK {
		t.Fatalf("Nest under the leaf: got %d, want %d: %s", nested.Code, http.StatusOK, nested.Body.String())
	}

	parent, err := server.getNodeFromPath("work")
	if err != nil {
		t.Fatalf("Failed to find the promoted node: %v", err)
	}
	if parent.Type != core.BranchNode {
		t.Errorf("The parent is still type %d, want a branch", parent.Type)
	}

	child, err := server.getNodeFromPath("work/task")
	if err != nil {
		t.Fatalf("Failed to find the nested node: %v", err)
	}
	if child.Type != core.LeafNode {
		t.Errorf("The child is type %d, want a leaf", child.Type)
	}

	// The child is reachable for the thing a leaf is for.
	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": "work/task", "event_id": "e1", "metadata": map[string]interface{}{},
	}).Code; code != http.StatusOK {
		t.Errorf("Start an event on the nested leaf: got %d, want %d", code, http.StatusOK)
	}
}

// A leaf that HOLDS something is not promoted. Converting it would strand its record on a node
// every event route refuses, so the request is refused instead — with a reason.
func TestCreateNodeRefusesToPromoteALeafThatRecordsEvents(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "tracked"}).Code; code != http.StatusOK {
		t.Fatalf("Create the leaf: got %d, want %d", code, http.StatusOK)
	}
	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": "tracked", "event_id": "e1", "metadata": map[string]interface{}{},
	}).Code; code != http.StatusOK {
		t.Fatalf("Start the event: got %d, want %d", code, http.StatusOK)
	}

	refused := post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "tracked/below"})
	if refused.Code != http.StatusConflict {
		t.Fatalf("Nest under a recording leaf: got %d, want %d", refused.Code, http.StatusConflict)
	}
	if !strings.Contains(refused.Body.String(), "records events or entries") {
		t.Errorf("The refusal does not say why: %s", refused.Body.String())
	}

	node, err := server.getNodeFromPath("tracked")
	if err != nil {
		t.Fatalf("Failed to find the node: %v", err)
	}
	if node.Type != core.LeafNode {
		t.Errorf("The refused node was converted anyway: type %d", node.Type)
	}
	if len(node.Events) != 1 {
		t.Errorf("The event on the refused node is gone: %d events", len(node.Events))
	}
}

// A planned event is persisted, so it survives the restart it is a plan across.
func TestPlannedEventSurvivesAReload(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)

	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "planning"}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}

	planned := post(t, server.handlePlanEvent, userID, map[string]interface{}{
		"path":       "planning",
		"event_id":   "next-week",
		"start_time": time.Now().Add(time.Hour).Format(time.RFC3339),
		"end_time":   time.Now().Add(2 * time.Hour).Format(time.RFC3339),
		"metadata":   map[string]interface{}{"title": "review"},
	})
	if planned.Code != http.StatusOK {
		t.Fatalf("Plan the event: got %d, want %d: %s", planned.Code, http.StatusOK, planned.Body.String())
	}

	loaded, err := LoadServer(types.ServerConfig{
		Process: types.ProcessInfo{ID: "stock_process", Name: "stock", LogPath: dir, DatabasePath: dir},
	})
	if err != nil {
		t.Fatalf("Failed to load the database: %v", err)
	}

	node, err := loaded.getNodeFromPath("planning")
	if err != nil {
		t.Fatalf("Failed to find the node after reload: %v", err)
	}
	if _, exists := node.PlannedEvents["next-week"]; !exists {
		t.Error("The planned event did not survive the reload")
	}
}

// A stranger cannot plan an event, and is told so rather than being handed a 500.
func TestPlanEventRefusesWithoutWritePermission(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "planning"}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}

	refused := post(t, server.handlePlanEvent, "someone-else", map[string]interface{}{
		"path":       "planning",
		"event_id":   "not-yours",
		"start_time": time.Now().Add(time.Hour).Format(time.RFC3339),
		"end_time":   time.Now().Add(2 * time.Hour).Format(time.RFC3339),
		"metadata":   map[string]interface{}{},
	})
	if refused.Code != http.StatusForbidden {
		t.Errorf("Plan as a stranger: got %d, want %d", refused.Code, http.StatusForbidden)
	}
}

// Node ids are NOT user ids. Every node in the forest used to be minted by the user generator and
// so carried a "user-" prefix, which made a node id unreadable as what it identifies.
func TestNodeIDsAreNotPrefixedAsUsers(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "work/projects/alpha"}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}

	seen := map[string]bool{}
	for _, path := range []string{"", "work", "work/projects", "work/projects/alpha"} {
		node, err := server.getNodeFromPath(path)
		if err != nil {
			t.Fatalf("Failed to find %q: %v", path, err)
		}
		if !strings.HasPrefix(node.ID, "node-") {
			t.Errorf("Node %q has id %q, want a node- prefix", path, node.ID)
		}
		if seen[node.ID] {
			t.Errorf("Node id %q was minted twice", node.ID)
		}
		seen[node.ID] = true
	}

	if !strings.HasPrefix(userID, "user-") {
		t.Errorf("User id %q lost its user- prefix", userID)
	}
}
