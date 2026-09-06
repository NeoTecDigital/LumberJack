package internal

import (
	"net/http"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// DELETE /nodes/{path}.
//
// The engine could author a graph it could never prune: 34 routes and two of them deletes, neither
// of which removed a node. These tests are about the decisions that removal needed rather than the
// removal itself — what happens to what is under a node, to what it holds, and above all to a node
// that two parents hold, which under multi-org is the ordinary case and not a corner.

// deleteNode drives the real route, which is where the path variable and the mode come from.
func deleteNode(t *testing.T, server *Server, userID, path, mode string) (int, nodeRemoval) {
	t.Helper()

	target := "/nodes/" + path
	if mode != "" {
		target += "?mode=" + mode
	}

	recorder := serveRoute(t, server, "DELETE", target, userID, nil)
	var removed nodeRemoval
	if recorder.Code == http.StatusOK {
		answered(t, recorder, &removed)
	}
	return recorder.Code, removed
}

// nodeExists reports whether a path still resolves.
func nodeExists(t *testing.T, server *Server, path string) bool {
	t.Helper()

	server.forestMutex.RLock()
	defer server.forestMutex.RUnlock()

	_, err := server.getNodeFromPath(path)
	return err == nil
}

// The two paths api_state_file_test.go's diamond fixture makes one node reachable by. Named here
// rather than repeated as literals, because every assertion below is about the SAME node being
// reached two ways and a typo in one of them would look like a passing test.
const (
	diamondViaAlpha = "org/alpha/shared"
	diamondViaBeta  = "org/beta/shared"
)

// DELETING A NODE TWO PARENTS HOLD IS REFUSED, AND THE EDGE ROUTE IS NOT.
//
// This is the decision the route exists to make. "Delete it" is ambiguous for a node reachable by
// two parents — remove the node, or remove the edge you arrived through — and the two are different
// operations: one of them takes the work away from an organisation that never asked for it. The
// route does not guess. It refuses, names DELETE /nodes/link, and leaves BOTH arms exactly as they
// were; the edge route then does the other operation, and the node survives on its remaining arm.
func TestDeletingADiamondNodeIsRefusedAndTheEdgeRouteIsNot(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	diamond(t, server, userID)
	viaAlpha, viaBeta := diamondViaAlpha, diamondViaBeta
	if !nodeExists(t, server, viaBeta) {
		t.Fatalf("The fixture did not build a diamond: %s does not resolve", viaBeta)
	}

	// Neither mode may take it. `cascade` is about what is UNDER a node; it is not permission to
	// resolve an ambiguity about the node itself.
	for _, mode := range []string{"", deleteModeCascade} {
		code, _ := deleteNode(t, server, userID, viaAlpha, mode)
		if code != http.StatusConflict {
			t.Fatalf("DELETE %s (mode=%q) on a two-parent node: got %d, want %d",
				viaAlpha, mode, code, http.StatusConflict)
		}
		if !nodeExists(t, server, viaAlpha) || !nodeExists(t, server, viaBeta) {
			t.Fatalf("A refused delete removed an arm: alpha=%t beta=%t",
				nodeExists(t, server, viaAlpha), nodeExists(t, server, viaBeta))
		}
	}

	// The refusal SAYS WHAT TO DO INSTEAD. A refusal that does not is a dead end, and a client that
	// hits one either gives up or starts guessing.
	recorder := serveRoute(t, server, "DELETE", "/nodes/"+viaAlpha, userID, nil)
	if !strings.Contains(recorder.Body.String(), "/nodes/link") {
		t.Errorf("The refusal does not name the route that removes an edge: %s", recorder.Body.String())
	}

	// The OTHER operation, through the route that has always owned it: the arm goes, the node stays.
	if code := post(t, server.handleUnlinkNode, userID, map[string]interface{}{
		"parent_path": "org/beta", "child_path": viaBeta,
	}).Code; code != http.StatusOK {
		t.Fatalf("DELETE /nodes/link on one arm: got %d", code)
	}
	if nodeExists(t, server, viaBeta) {
		t.Error("The edge was removed and the node is still reachable through it")
	}
	if !nodeExists(t, server, viaAlpha) {
		t.Fatal("Removing one arm removed the node: an unlink is not a delete")
	}

	// And now that one parent holds it, deleting the NODE is no longer ambiguous.
	if code, _ := deleteNode(t, server, userID, viaAlpha, ""); code != http.StatusOK {
		t.Fatalf("Deleting the node after unlinking the other arm: got %d, want %d", code, http.StatusOK)
	}
	if nodeExists(t, server, viaAlpha) {
		t.Error("The node was deleted and still resolves")
	}
}

// The default refuses a node that holds anything, and says what it holds.
//
// It is the default because it is the operation that cannot surprise anyone: it removes exactly
// what was named. A caller that means more asks for more.
func TestDeleteNodeRefusesWhatItHolds(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	leafFor(t, server, userID, "work/parent/child")
	withEvent := leafFor(t, server, userID, "work/tracked")
	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": withEvent, "event_id": "shift"})

	for _, held := range []struct {
		path string
		says string
	}{
		{"work/parent", "child"},
		{withEvent, "event"},
	} {
		recorder := serveRoute(t, server, "DELETE", "/nodes/"+held.path, userID, nil)
		if recorder.Code != http.StatusConflict {
			t.Errorf("DELETE %s: got %d, want %d", held.path, recorder.Code, http.StatusConflict)
		}
		if !strings.Contains(recorder.Body.String(), held.says) {
			t.Errorf("The refusal for %s does not say what it holds: %s", held.path, recorder.Body.String())
		}
		if !nodeExists(t, server, held.path) {
			t.Errorf("%s was refused and removed anyway", held.path)
		}
	}
}

// An empty node goes, the feed says so, and it stays gone across a restart.
func TestDeleteNodeRemovesAnEmptyNodeDurably(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/probe")

	code, removed := deleteNode(t, server, userID, path, "")
	if code != http.StatusOK {
		t.Fatalf("DELETE %s: got %d, want %d", path, code, http.StatusOK)
	}
	if removed.NodeCount != 1 || removed.Path != "forest/work/probe" {
		t.Errorf("The answer says %d node(s) at %q, want 1 at forest/work/probe", removed.NodeCount, removed.Path)
	}
	if nodeExists(t, server, path) {
		t.Fatal("The node still resolves after a 200")
	}

	announced := publishedOfKind(server, mutationNodeDeleted)
	if len(announced) != 1 || announced[0].NodePath != "forest/work/probe" {
		t.Fatalf("The stream announced %v for a deletion, want one node_deleted at forest/work/probe", announced)
	}

	if nodeExists(t, reloadServer(t, dir), path) {
		t.Error("The node came back after a restart: the removal was never persisted")
	}
}

// A cascade takes the subtree and the bytes it held.
//
// An attachment is stored inside the node's own document, so "delete the node" and "delete the
// file" are one act; there is no orphaned blob store left behind to sweep.
func TestCascadeRemovesTheSubtreeAndTheBytesItHeld(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)

	leafFor(t, server, userID, "work/site/room")
	tracked := leafFor(t, server, userID, "work/site/room/log")
	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": tracked, "event_id": "shift"})
	post(t, server.handleAppendToEvent, userID, map[string]interface{}{
		"path": tracked, "event_id": "shift", "content": "an entry",
	})
	attachmentID := uploadAttachment(t, server, userID, tracked, "report.txt", "bytes that must go")

	code, removed := deleteNode(t, server, userID, "work/site", deleteModeCascade)
	if code != http.StatusOK {
		t.Fatalf("Cascade: got %d, want %d", code, http.StatusOK)
	}
	if removed.NodeCount != 3 {
		t.Errorf("The cascade removed %d nodes, want 3: %v", removed.NodeCount, removed.Paths)
	}
	if removed.Events != 1 || removed.Entries != 1 || removed.Attachments != 1 {
		t.Errorf("The cascade reported %d events, %d entries, %d attachments; want 1, 1, 1",
			removed.Events, removed.Entries, removed.Attachments)
	}

	if nodeExists(t, server, tracked) {
		t.Error("A descendant survived the cascade")
	}
	if deleteAttachment(t, server, userID, tracked, attachmentID) != http.StatusNotFound {
		t.Error("The attachment is still reachable on a node that no longer exists")
	}

	// EVERY removed node is announced, not just the one the caller named: a client caches per node
	// path, so an unannounced descendant stays cacheable and correct-looking forever.
	if announced := publishedOfKind(server, mutationNodeDeleted); len(announced) != 3 {
		t.Errorf("The stream announced %d removals for a 3-node cascade", len(announced))
	}

	if nodeExists(t, reloadServer(t, dir), "work/site") {
		t.Error("The subtree came back after a restart")
	}
}

// A cascade does not take a descendant somebody else still holds.
//
// It removes only the nodes whose EVERY parent is going. A descendant hanging off a node outside
// the subtree loses that one edge and keeps its others, so it stays reachable — the same invariant
// DELETE /nodes/link enforces when it refuses to remove a node's last parent.
func TestCascadeLeavesADescendantAnotherParentStillHolds(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	shared := leafFor(t, server, userID, "org/alpha/team/shared")
	leafFor(t, server, userID, "org/beta/placeholder")
	if code := post(t, server.handleLinkNode, userID, map[string]interface{}{
		"parent_path": "org/beta", "child_path": shared,
	}).Code; code != http.StatusOK {
		t.Fatalf("Linking the second arm: got %d", code)
	}

	code, removed := deleteNode(t, server, userID, "org/alpha/team", deleteModeCascade)
	if code != http.StatusOK {
		t.Fatalf("Cascade over a subtree with a shared descendant: got %d, want %d", code, http.StatusOK)
	}
	if removed.NodeCount != 1 {
		t.Errorf("The cascade removed %d nodes, want 1: %v", removed.NodeCount, removed.Paths)
	}

	if nodeExists(t, server, shared) {
		t.Error("The removed subtree still resolves the shared node through the parent that went")
	}
	if !nodeExists(t, server, "org/beta/shared") {
		t.Fatal("A cascade stranded a node another parent still holds")
	}

	// And the edge that went is gone from BOTH ends: a Parents entry naming a node that no longer
	// exists is what every projection reports as a parent id.
	server.forestMutex.RLock()
	defer server.forestMutex.RUnlock()
	node, err := server.getNodeFromPath("org/beta/shared")
	if err != nil {
		t.Fatalf("Failed to reach the surviving node: %v", err)
	}
	if len(node.Parents) != 1 {
		t.Errorf("The surviving node names %d parents, want 1: %v", len(node.Parents), node.Parents)
	}
}

// The forest root is not deletable, and an unknown mode is refused rather than silently defaulted.
func TestDeleteNodeRefusesTheRootAndAnUnknownMode(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	leafFor(t, server, userID, "work/probe")

	if code, _ := deleteNode(t, server, userID, "forest", ""); code != http.StatusConflict {
		t.Errorf("DELETE the root: got %d, want %d", code, http.StatusConflict)
	}
	if server.forest == nil || len(server.forest.Children) == 0 {
		t.Fatal("Deleting the root emptied the forest")
	}

	// A misspelt mode must not be read as `refuse`: the caller would then be told the node holds
	// something, which is an answer about the forest and not about the mistake it made.
	code, _ := deleteNode(t, server, userID, "work/probe", "casacde")
	if code != http.StatusBadRequest {
		t.Errorf("DELETE with an unknown mode: got %d, want %d", code, http.StatusBadRequest)
	}
	if !nodeExists(t, server, "work/probe") {
		t.Error("An unknown mode removed the node anyway")
	}
}

// A cascade needs write on EVERY node it removes, not only on the one that was named.
//
// A cascade removes nodes the caller did not name, and a permission that was never granted on those
// is not granted by naming an ancestor of them.
func TestCascadeRefusesWithoutWriteOnEveryNodeItRemoves(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)

	leafFor(t, server, adminUserID, "work/branch/deep")
	limited := core.User{ID: core.GenerateUserID(), Username: "limited"}
	if err := server.forest.AssignUser(limited, core.ReadPermission); err != nil {
		t.Fatalf("Failed to add the limited user: %v", err)
	}
	if code := post(t, server.handleAssignUser, adminUserID, map[string]interface{}{
		"path": "work/branch", "assignee_id": limited.ID, "permission": int(core.WritePermission),
	}).Code; code != http.StatusOK {
		t.Fatalf("Granting write on the branch alone: got %d", code)
	}

	code, _ := deleteNode(t, server, limited.ID, "work/branch", deleteModeCascade)
	if code != http.StatusForbidden {
		t.Fatalf("Cascade by a caller who may not write the descendant: got %d, want %d",
			code, http.StatusForbidden)
	}
	if !nodeExists(t, server, "work/branch/deep") || !nodeExists(t, server, "work/branch") {
		t.Error("A refused cascade removed something")
	}
}

// DELETE /nodes/link still reaches the edge route, with a node delete registered on the same prefix.
//
// gorilla matches in REGISTRATION ORDER, so a `/nodes/{path:.*}` catch-all registered before the
// link route swallows it — and every attempt to remove an edge becomes an attempt to delete a node
// called "link". The two operations are different and the router must not be able to confuse them
// either.
func TestDeleteNodeLinkStillReachesTheEdgeRoute(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	diamond(t, server, userID)

	recorder := serveRoute(t, server, "DELETE", "/nodes/link", userID, map[string]interface{}{
		"parent_path": "org/beta", "child_path": diamondViaAlpha,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("DELETE /nodes/link: got %d, want %d: %s",
			recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if nodeExists(t, server, diamondViaBeta) {
		t.Error("The edge route answered 200 and the edge is still there")
	}
	if !nodeExists(t, server, diamondViaAlpha) {
		t.Error("DELETE /nodes/link deleted the node: the catch-all swallowed the edge route")
	}
	if len(publishedOfKind(server, mutationNodeDeleted)) != 0 {
		t.Error("Removing an edge announced a node deletion")
	}
}
