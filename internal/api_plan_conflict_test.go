package internal

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// THE DEFECT: POST /events/plan was an unconditional upsert into PlannedEvents, so planning over an
// id that is ALREADY A LIVE EVENT answered 200 and wrote a plan nobody can ever see.
//
// /query and /events flatten planned events together with live ones and drop the plan when the same
// id is in both maps — one id is one event, and the live one wins. GET /events therefore never
// shows it, POST /query never shows it, and only GET /forest, which dumps the raw maps, does. That
// is a success response for a write the caller cannot then observe: the same defect class as an
// attachment that uploads and will not download.
//
// The behaviour chosen here is REFUSAL. Making it discoverable would mean two different events
// under one id on one node, which is the thing the id is supposed to prevent.

// planEvent asks for a plan over a span, which is the only shape the route accepts.
func planEvent(t *testing.T, server *Server, userID, path, eventID string) *http.Response {
	t.Helper()

	start := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	end := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	return post(t, server.handlePlanEvent, userID, map[string]interface{}{
		"path": path, "event_id": eventID, "start_time": start, "end_time": end,
	}).Result()
}

// Planning over an event that has already started is a CONFLICT, and nothing is written.
func TestPlanningOverALiveEventIsRefusedAsAConflict(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/planning")

	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": path, "event_id": "shift",
	}).Code; code != http.StatusOK {
		t.Fatalf("Start the event: got %d, want %d", code, http.StatusOK)
	}

	refused := planEvent(t, server, userID, path, "shift")
	if refused.StatusCode != http.StatusConflict {
		t.Fatalf("POST /events/plan over a live event id: got %d, want %d",
			refused.StatusCode, http.StatusConflict)
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the node: %v", err)
	}
	if _, planned := node.PlannedEvents["shift"]; planned {
		t.Fatal("The refused plan was written to PlannedEvents anyway, where nothing can see it")
	}
}

// A plan for an id that is NOT live is still accepted, and re-planning a plan still moves it: the
// refusal is about a live event, not about planning twice.
func TestPlanningAFreshIDAndRePlanningAPlanBothSucceed(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/re-planning")

	first := planEvent(t, server, userID, path, "sprint-2")
	if first.StatusCode != http.StatusOK {
		t.Fatalf("POST /events/plan for a fresh id: got %d, want %d", first.StatusCode, http.StatusOK)
	}

	again := planEvent(t, server, userID, path, "sprint-2")
	if again.StatusCode != http.StatusOK {
		t.Fatalf("Re-planning a plan: got %d, want %d", again.StatusCode, http.StatusOK)
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the node: %v", err)
	}
	if _, planned := node.PlannedEvents["sprint-2"]; !planned {
		t.Fatal("The plan is not on the node")
	}
}

// Whatever a plan route accepts is FINDABLE afterwards. This is the invariant the conflict exists
// to hold: a 200 from /events/plan means /events can show it.
func TestAnAcceptedPlanIsVisibleToTheListingRoutes(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/visible-plans")

	if accepted := planEvent(t, server, userID, path, "sprint-3"); accepted.StatusCode != http.StatusOK {
		t.Fatalf("POST /events/plan: got %d, want %d", accepted.StatusCode, http.StatusOK)
	}

	listed := get(t, server.handleListEvents, userID, "/events?scope="+path)
	if listed.Code != http.StatusOK {
		t.Fatalf("GET /events: got %d, want %d: %s", listed.Code, http.StatusOK, listed.Body.String())
	}
	if !containsEventID(listed.Body.Bytes(), "sprint-3") {
		t.Fatalf("GET /events does not show the plan that was just accepted: %s", listed.Body.String())
	}
}

// containsEventID reports whether a query answer names an event id.
func containsEventID(body []byte, eventID string) bool {
	var answer queryResponse
	if err := json.Unmarshal(body, &answer); err != nil {
		return false
	}
	for _, result := range answer.Results {
		item, ok := result.(map[string]interface{})
		if !ok {
			continue
		}
		if item["event_id"] == eventID {
			return true
		}
	}
	return false
}
