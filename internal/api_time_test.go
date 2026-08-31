package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// get calls a handler the way authMiddleware would, on a GET with a query string.
func get(t *testing.T, handler http.HandlerFunc, userID string, target string) *httptest.ResponseRecorder {
	t.Helper()

	request := withUser(httptest.NewRequest("GET", target, nil), userID)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// start -> stop -> summary reports a real duration.
//
// It reported NOTHING before, on any instance, ever: StopTimeTracking wrote the sentinel
// "stop_time_entry" and GetTimeTrackingSummary paired a start against "end_time_entry", so no start
// was ever closed and the summary was always empty.
func TestTimeTrackingReportsADuration(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := "work/timed"

	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{"path": path}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}

	if code := post(t, server.handleStartTimeTracking, userID, map[string]interface{}{"path": path}).Code; code != http.StatusOK {
		t.Fatalf("Start time tracking: got %d, want %d", code, http.StatusOK)
	}

	// A measurable span, so that a zero duration is a failure rather than a rounding artefact.
	time.Sleep(2 * time.Millisecond)

	stopped := post(t, server.handleStopTimeTracking, userID, map[string]interface{}{"path": path})
	if stopped.Code != http.StatusOK {
		t.Fatalf("Stop time tracking: got %d, want %d: %s", stopped.Code, http.StatusOK, stopped.Body.String())
	}

	assertOneRealDuration(t, "stop response", stopped.Body.Bytes())

	// The same span read back over GET /time, which is the route a client actually asks with.
	summary := get(t, server.handleGetTimeTracking, userID, "/time?path="+path)
	if summary.Code != http.StatusOK {
		t.Fatalf("GET /time: got %d, want %d: %s", summary.Code, http.StatusOK, summary.Body.String())
	}
	assertOneRealDuration(t, "GET /time", summary.Body.Bytes())
}

// assertOneRealDuration fails unless the body is exactly one tracked span of non-zero length.
func assertOneRealDuration(t *testing.T, what string, body []byte) {
	t.Helper()

	var summary []map[string]interface{}
	if err := json.Unmarshal(body, &summary); err != nil {
		t.Fatalf("%s: failed to decode %q: %v", what, string(body), err)
	}
	if len(summary) != 1 {
		t.Fatalf("%s: got %d tracked spans, want 1: %s", what, len(summary), string(body))
	}

	duration, ok := summary[0]["duration"].(float64)
	if !ok {
		t.Fatalf("%s: no duration in %s", what, string(body))
	}
	if duration <= 0 {
		t.Errorf("%s: got duration %v, want a positive one", what, duration)
	}
}

// GET /time answers a query string. It used to decode a JSON body on a GET, which no conforming
// client sends, so every caller got 400 "EOF" and the route was unreachable.
func TestGetTimeTrackingReadsQueryParameters(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "work"}).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}

	// No body at all, which is the request an HTTP client makes for a GET.
	recorder := get(t, server.handleGetTimeTracking, userID, "/time?path=work")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /time with no body: got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	// An untracked node is an empty list, not null: a client can iterate the answer unconditionally.
	if body := recorder.Body.String(); body != "[]\n" {
		t.Errorf("GET /time on an untracked node: got %q, want an empty list", body)
	}

	if code := get(t, server.handleGetTimeTracking, userID, "/time?path=nowhere").Code; code != http.StatusNotFound {
		t.Errorf("GET /time on a path that does not exist: got %d, want %d", code, http.StatusNotFound)
	}
}

// The two sentinels are the ones the reader pairs on. This is the unit-level statement of the same
// fact, so a future rename of one of them fails here rather than silently emptying every summary.
func TestTimeTrackingSentinelsPair(t *testing.T) {
	node := core.NewNode(core.LeafNode, "timed")
	node.Users = []core.User{{ID: "u", Permissions: []core.Permission{core.WritePermission}}}

	if _, err := node.StartTimeTracking("u"); err != nil {
		t.Fatalf("Failed to start: %v", err)
	}
	if _, err := node.StopTimeTracking("u"); err != nil {
		t.Fatalf("Failed to stop: %v", err)
	}

	if summary := node.GetTimeTrackingSummary("u"); len(summary) != 1 {
		t.Fatalf("Got %d tracked spans, want 1", len(summary))
	}
	if node.Entries[0].Content != core.TimeEntryStart || node.Entries[1].Content != core.TimeEntryStop {
		t.Errorf("Entries carry %v and %v", node.Entries[0].Content, node.Entries[1].Content)
	}
}
