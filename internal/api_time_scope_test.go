package internal

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// THE DEFECT: GET /time was the ONE scoped route that did not mean a subtree.
//
// `scope` means "this node and everything under it" on /query, /aggregate, /entries and /events —
// and POST /query with select=time already reports spans recursively. GET /time read the same forest
// and answered [] for a branch whose child had tracked hours all week. A caller cannot tell that
// answer from "nobody tracked any time", which is the trap: an empty array that means "you asked the
// wrong way".
//
// Resolved TOWARDS the rest of the API: /time walks the subtree. The old single-node reading is
// still reachable, and is now something the caller asks for rather than something it gets by
// surprise — `depth=0`.

// trackASpan opens and closes a tracked span on one node, and returns the path.
func trackASpan(t *testing.T, server *Server, userID, path string) string {
	t.Helper()

	leafFor(t, server, userID, path)
	if code := post(t, server.handleStartTimeTracking, userID, map[string]interface{}{"path": path}).Code; code != http.StatusOK {
		t.Fatalf("Start time tracking on %s: got %d, want %d", path, code, http.StatusOK)
	}
	time.Sleep(2 * time.Millisecond)
	if code := post(t, server.handleStopTimeTracking, userID, map[string]interface{}{"path": path}).Code; code != http.StatusOK {
		t.Fatalf("Stop time tracking on %s: got %d, want %d", path, code, http.StatusOK)
	}
	return path
}

// timeSessions reads GET /time's answer, which is a bare array of sessions.
func timeSessions(t *testing.T, server *Server, userID, target string) []map[string]interface{} {
	t.Helper()

	answered := get(t, server.handleGetTimeTracking, userID, target)
	if answered.Code != http.StatusOK {
		t.Fatalf("GET %s: got %d, want %d: %s", target, answered.Code, http.StatusOK, answered.Body.String())
	}

	var sessions []map[string]interface{}
	if err := json.Unmarshal(answered.Body.Bytes(), &sessions); err != nil {
		t.Fatalf("GET %s did not answer an array: %v: %s", target, err, answered.Body.String())
	}
	return sessions
}

// A scope is a SUBTREE: time tracked on a child is reported when the parent is asked.
func TestTimeTrackingIsReportedForTheWholeSubtree(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	trackASpan(t, server, userID, "work/tracked/alpha")
	trackASpan(t, server, userID, "work/tracked/beta")

	sessions := timeSessions(t, server, userID, "/time?path=work/tracked")
	if len(sessions) != 2 {
		t.Fatalf("GET /time on a branch reported %d spans, want the 2 tracked beneath it", len(sessions))
	}
}

// Every session says WHICH NODE it was tracked on. A recursive answer whose items are not
// attributable is a list a caller cannot use — the same shape /query select=time already emits.
func TestEveryTimeSessionNamesItsNode(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	trackASpan(t, server, userID, "work/attributed/alpha")

	sessions := timeSessions(t, server, userID, "/time?path=work/attributed")
	if len(sessions) != 1 {
		t.Fatalf("Got %d spans, want 1", len(sessions))
	}
	if path, named := sessions[0]["node_path"].(string); !named || path == "" {
		t.Fatalf("A session does not name the node it was tracked on: %v", sessions[0])
	}
}

// depth=0 is the SCOPE ROOT ALONE, which is what this route used to do unconditionally.
func TestTimeTrackingAtDepthZeroIsTheScopeRootAlone(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	trackASpan(t, server, userID, "work/bounded/alpha")

	if sessions := timeSessions(t, server, userID, "/time?path=work/bounded&depth=0"); len(sessions) != 0 {
		t.Fatalf("GET /time?depth=0 on a branch reported %d spans, want 0", len(sessions))
	}
	if sessions := timeSessions(t, server, userID, "/time?path=work/bounded/alpha&depth=0"); len(sessions) != 1 {
		t.Fatalf("GET /time?depth=0 on the leaf itself reported %d spans, want 1", len(sessions))
	}
}

// `scope` is accepted by the name every other scoped route uses, and means the same thing as the
// `path` this route has always taken.
func TestTimeTrackingAcceptsScopeAndPathAlike(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	trackASpan(t, server, userID, "work/either-name/alpha")

	byPath := timeSessions(t, server, userID, "/time?path=work/either-name")
	byScope := timeSessions(t, server, userID, "/time?scope=work/either-name")
	if len(byPath) != len(byScope) || len(byPath) != 1 {
		t.Fatalf("path reported %d spans and scope reported %d, want 1 each", len(byPath), len(byScope))
	}
}

// THE CROSS-CHECK the units question is really about: /time and POST /query select=time read the
// same entries with two different span readers. They report the SAME spans over the same scope, or
// one of them is lying — and the durations are the same quantity in two documented units,
// nanoseconds on /time and milliseconds on /query.
func TestTimeRouteAndTimeQueryReportTheSameSpans(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	trackASpan(t, server, userID, "work/agreeing/alpha")
	trackASpan(t, server, userID, "work/agreeing/beta")

	sessions := timeSessions(t, server, userID, "/time?path=work/agreeing")

	queried := post(t, server.handleQuery, userID, map[string]interface{}{
		"select": "time", "scope": "work/agreeing",
	})
	if queried.Code != http.StatusOK {
		t.Fatalf("POST /query select=time: got %d, want %d: %s",
			queried.Code, http.StatusOK, queried.Body.String())
	}
	var answer queryResponse
	if err := json.Unmarshal(queried.Body.Bytes(), &answer); err != nil {
		t.Fatalf("POST /query did not answer JSON: %v", err)
	}

	if len(sessions) != len(answer.Results) {
		t.Fatalf("GET /time reported %d spans and POST /query select=time reported %d over the same scope",
			len(sessions), len(answer.Results))
	}

	// Matched on start_time, not on position. Ordering is a SEPARATE contract — /query sorts by
	// what the caller asked for and /time answers in walk order — so comparing by index would be
	// asserting something neither route promises.
	byStart := map[interface{}]map[string]interface{}{}
	for _, result := range answer.Results {
		item, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("A /query time result is not an object: %v", result)
		}
		byStart[item["start_time"]] = item
	}

	for _, session := range sessions {
		result, found := byStart[session["start_time"]]
		if !found {
			t.Fatalf("GET /time reports a span starting at %v that POST /query does not: %v",
				session["start_time"], byStart)
		}
		if session["end_time"] != result["end_time"] {
			t.Errorf("A span ends at %v on /time and %v on /query",
				session["end_time"], result["end_time"])
		}
		if session["node_path"] != result["node_path"] {
			t.Errorf("A span is on %v per /time and %v per /query",
				session["node_path"], result["node_path"])
		}

		// The unit statement, asserted rather than commented: /time's `duration` is NANOSECONDS and
		// /query's `duration_ms` is MILLISECONDS, and they describe one span.
		nanoseconds, ok := session["duration"].(float64)
		if !ok {
			t.Fatalf("A span has no numeric duration on /time: %v", session["duration"])
		}
		milliseconds, ok := result["duration_ms"].(float64)
		if !ok {
			t.Fatalf("A span has no numeric duration_ms on /query: %v", result["duration_ms"])
		}
		if int64(nanoseconds)/int64(time.Millisecond) != int64(milliseconds) {
			t.Errorf("A span is %v ns on /time and %v ms on /query, which are not the same span",
				nanoseconds, milliseconds)
		}
	}
}
