package internal

import (
	"net/http"
	"testing"
)

// POST /entries and PATCH /entries/{id}/metadata — the write half of the entry surface.
//
// An entry could be created (inside an event) and deleted, but never written at the node level with
// a parent and an order, nor moved once written. These tests hold the two new routes to the fields
// they exist for: a created entry comes back with a minted id AND the parent_id and rank it was
// given, and a patch rewrites rank, parent and metadata on the entry the id names.

// createEntry drives POST /entries and returns the created entry as the route projects it.
func createEntry(t *testing.T, server *Server, userID string, body map[string]interface{}) *entryView {
	t.Helper()
	recorder := serveRoute(t, server, "POST", "/entries", userID, body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /entries: got %d: %s", recorder.Code, recorder.Body.String())
	}
	var view entryView
	decodeBody(t, recorder, &view)
	return &view
}

// nodeEntries reads a node's own entries back through GET /nodes/{path}.
func nodeEntries(t *testing.T, server *Server, userID, path string) []entryView {
	t.Helper()
	recorder := serveRoute(t, server, "GET", "/nodes/"+path, userID, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /nodes/%s: got %d: %s", path, recorder.Code, recorder.Body.String())
	}
	var detail struct {
		Entries []entryView `json:"entries"`
	}
	decodeBody(t, recorder, &detail)
	return detail.Entries
}

// POST /entries creates a node-level entry carrying the parent and rank it was given, and answers a
// minted id — so a caller can name what it just wrote without reading it back by a moving index.
//
// OBSERVED RED before the routes were added to registerTestRoutes
// (go test ./internal/ -run CreateEntry):
//
//	api_entries_test.go:NN: POST /entries: got 405: <the router had no POST /entries>
func TestCreateEntryStoresParentAndRankAndMintsAnID(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "msg/room")

	created := createEntry(t, server, userID, map[string]interface{}{
		"path":      path,
		"content":   "a ranked, nested reply",
		"parent_id": "reply-to-abc",
		"rank":      "a1",
		"metadata":  map[string]interface{}{"pinned": true},
	})

	if created.ID == "" {
		t.Error("POST /entries answered an entry with no id")
	}
	if created.ParentID != "reply-to-abc" {
		t.Errorf("POST /entries answered parent_id %q, want %q", created.ParentID, "reply-to-abc")
	}
	if created.Rank != "a1" {
		t.Errorf("POST /entries answered rank %q, want %q", created.Rank, "a1")
	}

	// The entry is on the node, with the same id, parent and rank a read route returns.
	entries := nodeEntries(t, server, userID, path)
	if len(entries) != 1 {
		t.Fatalf("the node came back with %d entries, want 1", len(entries))
	}
	if entries[0].ID != created.ID || entries[0].ParentID != "reply-to-abc" || entries[0].Rank != "a1" {
		t.Errorf("GET returned id=%q parent=%q rank=%q, want %q/reply-to-abc/a1",
			entries[0].ID, entries[0].ParentID, entries[0].Rank, created.ID)
	}
}

// PATCH /entries/{id}/metadata rewrites rank and parent and merges metadata on the entry the id
// names, and answers the updated entry.
//
// OBSERVED RED before the routes were added to registerTestRoutes
// (go test ./internal/ -run PatchEntryRoute):
//
//	api_entries_test.go:NN: PATCH: got 404: <the router had no PATCH /entries/{id}/metadata>
func TestPatchEntryRouteUpdatesRankParentAndMetadata(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "msg/room")

	created := createEntry(t, server, userID, map[string]interface{}{
		"path": path, "content": "before", "parent_id": "old-parent", "rank": "a1",
		"metadata": map[string]interface{}{"colour": "red"},
	})

	recorder := serveRoute(t, server, "PATCH", "/entries/"+created.ID+"/metadata?path="+path, userID,
		map[string]interface{}{
			"rank":      "b7",
			"parent_id": "new-parent",
			"metadata":  map[string]interface{}{"colour": nil, "flag": "urgent"},
		})
	if recorder.Code != http.StatusOK {
		t.Fatalf("PATCH: got %d: %s", recorder.Code, recorder.Body.String())
	}

	var updated entryView
	decodeBody(t, recorder, &updated)
	if updated.ID != created.ID {
		t.Errorf("PATCH answered a different entry: %q, want %q", updated.ID, created.ID)
	}
	if updated.Rank != "b7" {
		t.Errorf("PATCH answered rank %q, want b7", updated.Rank)
	}
	if updated.ParentID != "new-parent" {
		t.Errorf("PATCH answered parent_id %q, want new-parent", updated.ParentID)
	}
	if _, present := updated.Metadata["colour"]; present {
		t.Error("PATCH did not delete the metadata key set to null")
	}
	if updated.Metadata["flag"] != "urgent" {
		t.Errorf("PATCH did not add the new metadata key: %v", updated.Metadata)
	}
}

// PATCH on an id nobody stored is a 404, not a 500: a client told the server broke retries something
// that can never succeed.
func TestPatchEntryRouteOnAnAbsentIDIs404(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "msg/room")

	recorder := serveRoute(t, server, "PATCH", "/entries/no-such-entry/metadata?path="+path, userID,
		map[string]interface{}{"rank": "z"})
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("PATCH an absent entry: got %d, want 404: %s", recorder.Code, recorder.Body.String())
	}
}
