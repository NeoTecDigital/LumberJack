package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// The discovery and canvas routes.

// serveRoute drives a request through the server's real routing table with a caller in context, so
// a test exercises the path variables and the method the route was registered under.
func serveRoute(t *testing.T, server *Server, method, target, userID string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Buffer
	if body == nil {
		reader = bytes.NewBuffer(nil)
	} else {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to encode the request: %v", err)
		}
		reader = bytes.NewBuffer(encoded)
	}

	request := httptest.NewRequest(method, target, reader)
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), "user_id", userID))

	recorder := httptest.NewRecorder()
	router := mux.NewRouter()
	registerTestRoutes(router, server)
	router.ServeHTTP(recorder, request)
	return recorder
}

// registerTestRoutes registers the routes under test WITHOUT the session middleware, because the
// caller is already in the request context. It mirrors the registration order in routes().
func registerTestRoutes(router *mux.Router, server *Server) {
	router.HandleFunc("/events", server.handleListEvents).Methods("GET")
	router.HandleFunc("/entries", server.handleListEntries).Methods("GET")
	router.HandleFunc("/nodes/link", server.handleLinkNode).Methods("POST")
	router.HandleFunc("/nodes/link", server.handleUnlinkNode).Methods("DELETE")
	router.HandleFunc("/nodes/{path:.*}/metadata", server.handlePatchNodeMetadata).Methods("PATCH")
	router.HandleFunc("/nodes/{path:.*}", server.handleGetNode).Methods("GET")
}

// decodeBody reads a JSON answer.
func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder, into interface{}) {
	t.Helper()

	if recorder.Code != http.StatusOK {
		t.Fatalf("got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), into); err != nil {
		t.Fatalf("Answer was not JSON: %v: %s", err, recorder.Body.String())
	}
}

// GET /events is the discovery primitive. POST /events needs an event_id the caller must already
// possess, so before this route there was no way to find out what events exist.
func TestListEventsDiscoversEventsNobodyNamed(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "discover/site")

	for _, eventID := range []string{"one", "two", "three"} {
		if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
			"path": path, "event_id": eventID,
		}).Code; code != http.StatusOK {
			t.Fatalf("Start %s: got %d", eventID, code)
		}
	}
	if code := post(t, server.handleEndEvent, userID, map[string]interface{}{
		"path": path, "event_id": "one",
	}).Code; code != http.StatusOK {
		t.Fatalf("End one: got %d", code)
	}

	var all queryResponse
	decodeBody(t, serveRoute(t, server, "GET", "/events?scope=discover", userID, nil), &all)
	if all.Total != 3 {
		t.Errorf("GET /events found %d events, want 3", all.Total)
	}

	var ongoing queryResponse
	decodeBody(t, serveRoute(t, server, "GET", "/events?scope=discover&status=ongoing", userID, nil), &ongoing)
	if ongoing.Total != 2 {
		t.Errorf("GET /events?status=ongoing found %d, want 2", ongoing.Total)
	}

	var finished queryResponse
	decodeBody(t, serveRoute(t, server, "GET", "/events?scope=discover&status=finished", userID, nil), &finished)
	if finished.Total != 1 {
		t.Errorf("GET /events?status=finished found %d, want 1", finished.Total)
	}
	if got := finished.Results[0].(map[string]interface{})["event_id"]; got != "one" {
		t.Errorf("The finished event was %v, want one", got)
	}
}

// GET /entries is the feed primitive, and `since` is the bound a feed polls with.
func TestListEntriesIsAFeed(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "feed/site")

	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "run"})
	for index := 0; index < 3; index++ {
		post(t, server.handleAppendToEvent, userID, map[string]interface{}{
			"path": path, "event_id": "run", "content": fmt.Sprintf("entry-%d", index),
		})
	}

	var all queryResponse
	decodeBody(t, serveRoute(t, server, "GET", "/entries?scope=feed", userID, nil), &all)
	if all.Total != 3 {
		t.Fatalf("GET /entries found %d entries, want 3", all.Total)
	}

	// A feed is read forwards, so the first result is the oldest.
	if got := all.Results[0].(map[string]interface{})["content"]; got != "entry-0" {
		t.Errorf("The feed began at %v, want entry-0", got)
	}

	// Everything since the second entry's own timestamp: that entry and the one after it.
	since := fmt.Sprintf("%v", all.Results[1].(map[string]interface{})["timestamp"])
	var recent queryResponse
	decodeBody(t, serveRoute(t, server, "GET", "/entries?scope=feed&since="+since, userID, nil), &recent)
	if recent.Total != 2 {
		t.Errorf("GET /entries?since found %d, want 2", recent.Total)
	}
}

// GET /nodes/{path} answers one node without pulling the subtree under it.
func TestGetNodeAnswersOneNode(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	leafFor(t, server, userID, "one/two/three")
	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": "one/two/three", "event_id": "here"})

	var answer map[string]interface{}
	decodeBody(t, serveRoute(t, server, "GET", "/nodes/one/two", userID, nil), &answer)

	// The path comes back CANONICAL — rooted at the forest's own name — whichever of the two forms
	// the request was made in. See node_path.go.
	node := answer["node"].(map[string]interface{})
	if node["path"] != "forest/one/two" || node["name"] != "two" {
		t.Errorf("Answered %v, want forest/one/two", node)
	}

	children := answer["children"].([]interface{})
	if len(children) != 1 || children[0].(map[string]interface{})["path"] != "forest/one/two/three" {
		t.Errorf("Children were %v, want the one node below", children)
	}

	// The grandchild's EVENTS are not here. This route answers one node.
	if len(answer["events"].([]interface{})) != 0 {
		t.Errorf("GET /nodes/one/two carried the subtree's events: %v", answer["events"])
	}

	// A caller with no permission is refused rather than answered.
	readerID := addReadUser(t, server, "outsider")
	target, err := server.getNodeFromPath("one/two")
	if err != nil {
		t.Fatalf("Failed to find the node: %v", err)
	}
	target.Users = nil
	if code := serveRoute(t, server, "GET", "/nodes/one/two", readerID, nil).Code; code != http.StatusForbidden {
		t.Errorf("GET /nodes for a caller with no permission: got %d, want %d", code, http.StatusForbidden)
	}
}

// PATCH /nodes/{path}/metadata MERGES.
//
// Replace is the wrong verb: two surfaces annotate the same node, and a replace means whichever
// saved last silently discarded the other's work.
func TestNodeMetadataMerges(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	leafFor(t, server, userID, "canvas/box")

	layout := map[string]interface{}{"x": 10.0, "y": 20.0, "w": 100.0, "h": 60.0, "shape": "rect", "color": "#334455", "collapsed": false}
	decodeBody(t, serveRoute(t, server, "PATCH", "/nodes/canvas/box/metadata", userID, map[string]interface{}{
		CanvasMetadataKey: layout,
	}), &map[string]interface{}{})

	// A SECOND surface writes a different key. The layout must survive it.
	var merged map[string]interface{}
	decodeBody(t, serveRoute(t, server, "PATCH", "/nodes/canvas/box/metadata", userID, map[string]interface{}{
		"owner": "richard",
	}), &merged)

	metadata := merged["metadata"].(map[string]interface{})
	if metadata["owner"] != "richard" {
		t.Errorf("The second patch was not applied: %v", metadata)
	}
	if _, kept := metadata[CanvasMetadataKey]; !kept {
		t.Fatalf("The second patch replaced the layout instead of merging: %v", metadata)
	}

	// A null DELETES a key, which is the only way a merge can remove anything.
	decodeBody(t, serveRoute(t, server, "PATCH", "/nodes/canvas/box/metadata", userID, map[string]interface{}{
		"owner": nil,
	}), &merged)
	if _, present := merged["metadata"].(map[string]interface{})["owner"]; present {
		t.Error("A null did not remove the key")
	}

	// AND IT SURVIVES A RESTART, which is the whole point of persisting a layout.
	restarted := reloadServer(t, dir)
	node, err := restarted.getNodeFromPath("canvas/box")
	if err != nil {
		t.Fatalf("Failed to find the node after a restart: %v", err)
	}

	restored, present := node.Metadata[CanvasMetadataKey].(map[string]interface{})
	if !present {
		t.Fatalf("The layout did not survive the restart: %v", node.Metadata)
	}
	for key, want := range layout {
		if restored[key] != want {
			t.Errorf("Layout %s came back as %v, want %v", key, restored[key], want)
		}
	}
}

// POST /nodes/link makes the multi-parent edge that was creatable in core and exposed nowhere.
func TestLinkNodeMakesAMultiParentEdge(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	leafFor(t, server, userID, "acme/projects/alpha")
	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": "personal/work", "type": "branch",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create the second parent: got %d", code)
	}

	if code := serveRoute(t, server, "POST", "/nodes/link", userID, map[string]string{
		"parent_path": "personal/work", "child_path": "acme/projects/alpha",
	}).Code; code != http.StatusOK {
		t.Fatalf("POST /nodes/link: got %d", code)
	}

	// The same node is now reachable from both, and the edge SURVIVES A RESTART.
	restarted := reloadServer(t, dir)
	viaAcme, err := restarted.getNodeFromPath("acme/projects/alpha")
	if err != nil {
		t.Fatalf("Failed to find the node by its first path: %v", err)
	}
	viaPersonal, err := restarted.getNodeFromPath("personal/work/alpha")
	if err != nil {
		t.Fatalf("Failed to find the node by its second path: %v", err)
	}
	if viaAcme.ID != viaPersonal.ID {
		t.Errorf("The two paths reached different nodes: %s and %s", viaAcme.ID, viaPersonal.ID)
	}
	if len(viaAcme.Parents) != 2 {
		t.Errorf("The node has %d parents, want 2", len(viaAcme.Parents))
	}

	// And a query counts it ONCE.
	if got := queryOf(t, restarted, adminID(t, restarted), map[string]interface{}{"select": "nodes"}); got.Total != 6 {
		// forest, acme, acme/projects, alpha, personal, personal/work
		t.Errorf("Counted %d nodes over the linked DAG, want 6: %v", got.Total, pathsOf(t, got.Results))
	}

	// Linking again is idempotent.
	if code := serveRoute(t, server, "POST", "/nodes/link", userID, map[string]string{
		"parent_path": "personal/work", "child_path": "acme/projects/alpha",
	}).Code; code != http.StatusOK {
		t.Error("Linking the same edge twice was refused")
	}
}

// A link that would make a CYCLE is refused.
//
// The traversals carry visit sets and would survive one, but the state file is JSON and JSON cannot
// hold a cycle: the persist that acknowledges the edge would recurse until the stack ran out.
func TestLinkRefusesACycle(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	leafFor(t, server, userID, "top/middle/bottom")
	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": "top/middle/bottom", "type": "branch",
	}).Code; code != http.StatusConflict && code != http.StatusOK {
		t.Fatalf("Prepare the branch: got %d", code)
	}

	bottom, err := server.getNodeFromPath("top/middle/bottom")
	if err != nil {
		t.Fatalf("Failed to find the node: %v", err)
	}
	bottom.Type = 1 // branch, so it can hold a child at all

	answer := serveRoute(t, server, "POST", "/nodes/link", userID, map[string]string{
		"parent_path": "top/middle/bottom", "child_path": "top",
	})
	if answer.Code != http.StatusConflict {
		t.Errorf("Linking an ancestor under its own descendant: got %d, want %d: %s",
			answer.Code, http.StatusConflict, answer.Body.String())
	}

	// A node cannot be its own parent either.
	if code := serveRoute(t, server, "POST", "/nodes/link", userID, map[string]string{
		"parent_path": "top", "child_path": "top",
	}).Code; code != http.StatusBadRequest {
		t.Errorf("Linking a node to itself: got %d, want %d", code, http.StatusBadRequest)
	}
}

// DELETE /nodes/link removes an edge, and REFUSES to remove the last one.
//
// A node whose only parent is removed is unreachable from the root and would be persisted by
// nothing — a deletion nobody asked for, reported as a successful unlink.
func TestUnlinkRefusesToStrandANode(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	leafFor(t, server, userID, "acme/alpha")
	post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "personal", "type": "branch"})

	stranding := serveRoute(t, server, "DELETE", "/nodes/link", userID, map[string]string{
		"parent_path": "acme", "child_path": "acme/alpha",
	})
	if stranding.Code != http.StatusConflict {
		t.Errorf("Unlinking a node's only parent: got %d, want %d", stranding.Code, http.StatusConflict)
	}
	if _, err := server.getNodeFromPath("acme/alpha"); err != nil {
		t.Errorf("The refused unlink removed the node anyway: %v", err)
	}

	// With a second parent, the first edge can go.
	if code := serveRoute(t, server, "POST", "/nodes/link", userID, map[string]string{
		"parent_path": "personal", "child_path": "acme/alpha",
	}).Code; code != http.StatusOK {
		t.Fatalf("Link: got %d", code)
	}
	if code := serveRoute(t, server, "DELETE", "/nodes/link", userID, map[string]string{
		"parent_path": "acme", "child_path": "acme/alpha",
	}).Code; code != http.StatusOK {
		t.Fatalf("Unlink with a second parent present: got %d", code)
	}
	if _, err := server.getNodeFromPath("acme/alpha"); err == nil {
		t.Error("The node is still under the parent it was unlinked from")
	}
	if _, err := server.getNodeFromPath("personal/alpha"); err != nil {
		t.Errorf("The node lost its remaining parent too: %v", err)
	}
}

// Both ends of an edge are checked. An edge changes the parent and the child.
func TestEdgeRoutesCheckBothEnds(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)
	readerID := addReadUser(t, server, "reader")
	leafFor(t, server, adminUserID, "acme/alpha")
	post(t, server.handleCreateNode, adminUserID, map[string]interface{}{"path": "personal", "type": "branch"})

	if code := serveRoute(t, server, "POST", "/nodes/link", readerID, map[string]string{
		"parent_path": "personal", "child_path": "acme/alpha",
	}).Code; code != http.StatusForbidden {
		t.Errorf("A reader linked a node: got %d, want %d", code, http.StatusForbidden)
	}

	// Neither end named is a refusal, not a quiet 200 for an edge from the root to itself.
	if code := serveRoute(t, server, "POST", "/nodes/link", adminUserID, map[string]string{}).Code; code != http.StatusBadRequest {
		t.Errorf("A link naming neither end: got %d, want %d", code, http.StatusBadRequest)
	}
}

// An appended entry's content comes back as what was sent.
//
// core.AppendToEvent's third argument is the CONTENT and it wraps whatever it is given in an entry
// of its own. The handler used to build a whole core.Entry and pass that, so a client that appended
// "inspection complete" read back an object with a timestamp and a user id nested inside it — and
// every text search over entry content was searching the string form of a struct.
func TestAppendedContentIsWhatWasSent(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "content/site")

	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "run"})
	if code := post(t, server.handleAppendToEvent, userID, map[string]interface{}{
		"path": path, "event_id": "run", "content": "inspection complete",
		"metadata": map[string]interface{}{"grade": "a"},
	}).Code; code != http.StatusOK {
		t.Fatalf("Append: got %d", code)
	}

	var entries []entryView
	decoded := post(t, server.handleGetEventEntries, userID, map[string]interface{}{
		"path": path, "event_id": "run",
	})
	if err := json.Unmarshal(decoded.Body.Bytes(), &entries); err != nil {
		t.Fatalf("POST /events did not answer JSON: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Read back %d entries, want 1", len(entries))
	}
	if entries[0].Content != "inspection complete" {
		t.Errorf("content came back as %#v, want the string that was sent", entries[0].Content)
	}
	if entries[0].Metadata["grade"] != "a" {
		t.Errorf("metadata came back as %v", entries[0].Metadata)
	}

	// And it is therefore searchable as text, which is what /query's `text` predicate is for.
	found := queryOf(t, server, userID, map[string]interface{}{
		"select": "entries", "scope": "content", "where": map[string]interface{}{"text": "inspection"},
	})
	if found.Total != 1 {
		t.Errorf("Text search over entry content found %d, want 1", found.Total)
	}
}
