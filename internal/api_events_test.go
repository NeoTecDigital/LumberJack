package internal

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// leafFor creates a leaf the admin can track events on, and returns its path.
func leafFor(t *testing.T, server *Server, adminUserID, path string) string {
	t.Helper()

	if code := post(t, server.handleCreateNode, adminUserID, map[string]interface{}{"path": path}).Code; code != http.StatusOK {
		t.Fatalf("Create node %s: got %d, want %d", path, code, http.StatusOK)
	}
	return path
}

// A refusal is a 403 on EVERY event route.
//
// core.StartEvent and core.AppendToEvent do check for write permission, so the hole was closed —
// but their refusal came back as 500, which says the server broke rather than that the caller may
// not, and disagreed with /events/plan and /events/end.
func TestEventRoutesRefuseWithoutWritePermissionAsForbidden(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)

	// Added to the root BEFORE the leaf exists, so the leaf inherits the reader at ReadPermission.
	readerID := addReadUser(t, server, "reader")
	path := leafFor(t, server, adminUserID, "work/read-only")

	// An event the admin made, so that append and end have something real to be refused on.
	if code := post(t, server.handleStartEvent, adminUserID, map[string]interface{}{
		"path": path, "event_id": "existing",
	}).Code; code != http.StatusOK {
		t.Fatalf("Admin start event: got %d, want %d", code, http.StatusOK)
	}

	refusals := []struct {
		name    string
		handler http.HandlerFunc
		body    map[string]interface{}
	}{
		{"POST /events/start", server.handleStartEvent, map[string]interface{}{
			"path": path, "event_id": "refused",
		}},
		{"POST /events/append", server.handleAppendToEvent, map[string]interface{}{
			"path": path, "event_id": "existing", "content": "refused",
		}},
		{"POST /events/end", server.handleEndEvent, map[string]interface{}{
			"path": path, "event_id": "existing",
		}},
		{"POST /events/plan", server.handlePlanEvent, map[string]interface{}{
			"path":       path,
			"event_id":   "refused",
			"start_time": time.Now().Add(time.Hour).Format(time.RFC3339),
			"end_time":   time.Now().Add(2 * time.Hour).Format(time.RFC3339),
		}},
	}

	for _, refusal := range refusals {
		recorder := post(t, refusal.handler, readerID, refusal.body)
		if recorder.Code != http.StatusForbidden {
			t.Errorf("%s as a reader: got %d, want %d: %s",
				refusal.name, recorder.Code, http.StatusForbidden, recorder.Body.String())
		}
	}

	// The refusals really refused: nothing was written.
	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to read back the node: %v", err)
	}
	if _, created := node.Events["refused"]; created {
		t.Error("A refused start created an event anyway")
	}
	if len(node.PlannedEvents) != 0 {
		t.Errorf("A refused plan created %d planned event(s)", len(node.PlannedEvents))
	}
	if existing := node.Events["existing"]; len(existing.Entries) != 0 || existing.EndTime != nil {
		t.Error("A refused append or end changed the event anyway")
	}
}

// An event must be NAMED.
//
// A request with no event_id silently created an event keyed on the empty string, which no client
// could then end or append to and which POST /events reported back as an event with no name.
func TestEventRoutesRejectAnUnnamedEvent(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)
	path := leafFor(t, server, adminUserID, "work/named")

	unnamed := []string{"", "   ", "\t\n"}
	for _, eventID := range unnamed {
		started := post(t, server.handleStartEvent, adminUserID, map[string]interface{}{
			"path": path, "event_id": eventID,
		})
		if started.Code != http.StatusBadRequest {
			t.Errorf("POST /events/start with event_id %q: got %d, want %d: %s",
				eventID, started.Code, http.StatusBadRequest, started.Body.String())
		}

		planned := post(t, server.handlePlanEvent, adminUserID, map[string]interface{}{
			"path":       path,
			"event_id":   eventID,
			"start_time": time.Now().Add(time.Hour).Format(time.RFC3339),
			"end_time":   time.Now().Add(2 * time.Hour).Format(time.RFC3339),
		})
		if planned.Code != http.StatusBadRequest {
			t.Errorf("POST /events/plan with event_id %q: got %d, want %d: %s",
				eventID, planned.Code, http.StatusBadRequest, planned.Body.String())
		}

		// /events/end belongs in this table for the same reason it was missing from it: the guard
		// that was absent from handleEndEvent survived precisely because nothing walked it here. An
		// unnamed end answered "event not found" as a 500 — a server fault for a request the caller
		// malformed — where /events/start and /events/plan both answer 400.
		ended := post(t, server.handleEndEvent, adminUserID, map[string]interface{}{
			"path": path, "event_id": eventID,
		})
		if ended.Code != http.StatusBadRequest {
			t.Errorf("POST /events/end with event_id %q: got %d, want %d: %s",
				eventID, ended.Code, http.StatusBadRequest, ended.Body.String())
		}
	}

	// A request that names no event is one that names no event, not one that names "".
	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to read back the node: %v", err)
	}
	if len(node.Events) != 0 {
		t.Errorf("The node holds %d event(s) after only unnamed requests: %v", len(node.Events), node.Events)
	}
	if len(node.PlannedEvents) != 0 {
		t.Errorf("The node holds %d planned event(s) after only unnamed requests", len(node.PlannedEvents))
	}

	// A named one still works, so the check refuses the empty name and nothing else.
	if code := post(t, server.handleStartEvent, adminUserID, map[string]interface{}{
		"path": path, "event_id": "named",
	}).Code; code != http.StatusOK {
		t.Fatalf("POST /events/start with a name: got %d, want %d", code, http.StatusOK)
	}
}

// Reading the entries of an event takes read permission ON THAT NODE.
//
// The handler asked for nothing at all — no caller, no permission — and core.GetEventEntries checks
// nothing either, so any valid session could read the entries of any event anywhere in the forest.
func TestGetEventEntriesRequiresReadPermission(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)
	path := leafFor(t, server, adminUserID, "work/private")

	if code := post(t, server.handleStartEvent, adminUserID, map[string]interface{}{
		"path": path, "event_id": "private",
	}).Code; code != http.StatusOK {
		t.Fatalf("Start event: got %d, want %d", code, http.StatusOK)
	}
	if code := post(t, server.handleAppendToEvent, adminUserID, map[string]interface{}{
		"path": path, "event_id": "private", "content": "a private note",
	}).Code; code != http.StatusOK {
		t.Fatalf("Append to event: got %d, want %d", code, http.StatusOK)
	}

	// Added to the root AFTER the leaf was made, so this user holds nothing on the leaf itself.
	outsiderID := addReadUser(t, server, "outsider")

	recorder := post(t, server.handleGetEventEntries, outsiderID, map[string]interface{}{
		"path": path, "event_id": "private",
	})
	if recorder.Code != http.StatusForbidden {
		t.Errorf("POST /events as an outsider: got %d, want %d: %s",
			recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	if body := recorder.Body.String(); strings.Contains(body, "a private note") {
		t.Error("The refused read returned the entry anyway")
	}

	// An anonymous caller is refused before permission is even considered.
	anonymous := post(t, server.handleGetEventEntries, "", map[string]interface{}{
		"path": path, "event_id": "private",
	})
	if anonymous.Code != http.StatusUnauthorized {
		t.Errorf("POST /events with no session: got %d, want %d", anonymous.Code, http.StatusUnauthorized)
	}

	// The admin, who does hold the node, still reads it.
	allowed := post(t, server.handleGetEventEntries, adminUserID, map[string]interface{}{
		"path": path, "event_id": "private",
	})
	if allowed.Code != http.StatusOK {
		t.Fatalf("POST /events as the owner: got %d, want %d: %s",
			allowed.Code, http.StatusOK, allowed.Body.String())
	}
	if !strings.Contains(allowed.Body.String(), "a private note") {
		t.Errorf("The permitted read returned %q", allowed.Body.String())
	}
}
