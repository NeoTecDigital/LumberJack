package internal

import (
	"net/http"
	"testing"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// The state file and the graph it is supposed to hold.
//
// THE DEFECT: the forest is a DAG, and JSON is a TREE. A node with two parents was written out
// under each of them, so a restart unmarshalled it TWICE — two objects carrying one id. Every route
// then silently operated on whichever of the two the path it was given happened to reach: an event
// started via one parent was invisible via the other, the entry counts disagreed, and a permission
// granted on shared work applied to only one of the two organisations that shared it.

// diamond builds the smallest fork: one leaf that genuinely belongs to two branches.
func diamond(t *testing.T, server *Server, userID string) {
	t.Helper()

	leafFor(t, server, userID, "org/alpha/shared")
	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": "org/beta", "type": "branch",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create org/beta: got %d, want %d", code, http.StatusOK)
	}
	if code := post(t, server.handleLinkNode, userID, map[string]interface{}{
		"parent_path": "org/beta", "child_path": "org/alpha/shared",
	}).Code; code != http.StatusOK {
		t.Fatalf("Link the shared node under org/beta: got %d, want %d", code, http.StatusOK)
	}
}

// A shared node comes back from the state file as ONE object.
func TestReloadKeepsASharedNodeOneObject(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	diamond(t, server, userID)

	viaAlpha, err := server.getNodeFromPath("org/alpha/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via alpha: %v", err)
	}
	viaBeta, err := server.getNodeFromPath("org/beta/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via beta: %v", err)
	}
	if viaAlpha != viaBeta {
		t.Fatalf("The shared node is already two objects in memory")
	}

	loaded := reloadServer(t, dir)
	alpha, err := loaded.getNodeFromPath("org/alpha/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via alpha after a restart: %v", err)
	}
	beta, err := loaded.getNodeFromPath("org/beta/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via beta after a restart: %v", err)
	}

	if alpha.ID != beta.ID {
		t.Fatalf("The two paths reached different nodes: %s and %s", alpha.ID, beta.ID)
	}
	if alpha != beta {
		t.Errorf("A restart forked node %s into two objects with one id", alpha.ID)
	}
}

// A change made through one parent is a change to the node, not to one of its copies.
func TestReloadedSharedNodeIsChangedThroughEitherParent(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	diamond(t, server, userID)

	loaded := reloadServer(t, dir)
	if code := post(t, loaded.handleStartEvent, userID, map[string]interface{}{
		"path": "org/alpha/shared", "event_id": "shift",
	}).Code; code != http.StatusOK {
		t.Fatalf("Start an event via alpha: got %d, want %d", code, http.StatusOK)
	}

	// The SAME event, asked for through the other parent.
	answer := post(t, loaded.handleGetEventEntries, userID, map[string]interface{}{
		"path": "org/beta/shared", "event_id": "shift",
	})
	if answer.Code != http.StatusOK {
		t.Errorf("The event started via alpha is invisible via beta: got %d, want %d: %s",
			answer.Code, http.StatusOK, answer.Body.String())
	}

	// And a grant on shared work applies to everyone who shares it, not to one fork of it.
	reader := addReadUser(t, loaded, "auditor")
	viaAlpha, err := loaded.getNodeFromPath("org/alpha/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via alpha: %v", err)
	}
	if err := viaAlpha.AssignUser(core.User{ID: reader, Username: "auditor"}, core.WritePermission); err != nil {
		t.Fatalf("Failed to grant on the shared node: %v", err)
	}

	viaBeta, err := loaded.getNodeFromPath("org/beta/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via beta: %v", err)
	}
	if !viaBeta.CheckPermission(reader, core.WritePermission) {
		t.Error("A grant made on the shared node via alpha does not hold via beta")
	}
}
