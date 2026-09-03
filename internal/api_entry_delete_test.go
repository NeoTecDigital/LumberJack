package internal

import (
	"net/http"
	"strings"
	"testing"
)

// DELETE /entries/{id} and DELETE /time/{id}.
//
// Neither could be written before entries had ids: an index is invalidated by every insertion and
// deletion before it, so a delete keyed on one removes whatever has since slid into the position.
// These tests are about the two things that decides — that the id names the entry rather than the
// slot, and that half a tracked span is not a thing that may be removed.

// deleteEntry drives DELETE /entries/{id} on a node.
func deleteEntry(t *testing.T, server *Server, userID, path, entryID string) *httpAnswer {
	t.Helper()
	return answerOf(t, serveRoute(t, server, "DELETE", "/entries/"+entryID+"?path="+path, userID, nil))
}

// deleteTimeSpan drives DELETE /time/{id} on a node.
func deleteTimeSpan(t *testing.T, server *Server, userID, path, spanID string) *httpAnswer {
	t.Helper()
	return answerOf(t, serveRoute(t, server, "DELETE", "/time/"+spanID+"?path="+path, userID, nil))
}

// httpAnswer is a status together with the body that came with it, so a test can assert on both
// without deciding in advance which one it is going to need.
type httpAnswer struct {
	code int
	body string
}

// answerOf reads a recorder into an answer.
func answerOf(t *testing.T, recorder interface {
	Result() *http.Response
}) *httpAnswer {
	t.Helper()

	response := recorder.Result()
	defer response.Body.Close()

	buffer := make([]byte, 4096)
	read, _ := response.Body.Read(buffer)
	return &httpAnswer{code: response.StatusCode, body: string(buffer[:read])}
}

// trackedSpans is every span GET /time reports on a node for the caller.
func trackedSpans(t *testing.T, server *Server, userID, path string) []map[string]interface{} {
	t.Helper()

	var spans []map[string]interface{}
	decodeBody(t, get(t, server.handleGetTimeTracking, userID, "/time?scope="+path), &spans)
	return spans
}

// The id names the ENTRY, not the slot it happens to be in.
//
// This is the property an index cannot have. Delete the first of three entries and the second is at
// index 0 — so a second delete against "index 1" would take the third, which is not what anybody
// asked for. Against ids, each delete takes exactly the entry it names.
func TestDeleteEntryRemovesTheEntryTheIDNamesNotTheSlot(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "msg/room")

	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "thread"})
	for _, text := range []string{"first", "second", "third"} {
		post(t, server.handleAppendToEvent, userID, map[string]interface{}{
			"path": path, "event_id": "thread", "content": text,
		})
	}

	ids := idsOf(entriesOf(t, server, userID, path, "thread"))
	if answer := deleteEntry(t, server, userID, path, ids[0]); answer.code != http.StatusOK {
		t.Fatalf("DELETE the first entry: got %d: %s", answer.code, answer.body)
	}
	// The SECOND id, which is now at index 0. An index-addressed delete asked to remove "the entry
	// that was second" would take "third" here.
	if answer := deleteEntry(t, server, userID, path, ids[1]); answer.code != http.StatusOK {
		t.Fatalf("DELETE the second entry by id: got %d: %s", answer.code, answer.body)
	}

	left := entriesOf(t, server, userID, path, "thread")
	if len(left) != 1 {
		t.Fatalf("Two deletes of three entries left %d", len(left))
	}
	if left[0].Content != "third" || left[0].ID != ids[2] {
		t.Errorf("The surviving entry is %v (%s), want third (%s)", left[0].Content, left[0].ID, ids[2])
	}

	announced := publishedOfKind(server, mutationEntryDeleted)
	if len(announced) != 2 {
		t.Fatalf("The stream announced %d entry deletions for two deletes", len(announced))
	}
	if announced[0].EntryID != ids[0] || announced[0].EventID != "thread" {
		t.Errorf("The stream announced entry %q of event %q, want %q of thread",
			announced[0].EntryID, announced[0].EventID, ids[0])
	}

	restarted := reloadServer(t, dir)
	if remaining := entriesOf(t, restarted, userID, path, "thread"); len(remaining) != 1 {
		t.Errorf("A restart read back %d entries, want 1: the deletes were not persisted", len(remaining))
	}

	// An id that is not there is a 404, not a 500: a client told the server broke retries something
	// that can never succeed.
	if answer := deleteEntry(t, server, userID, path, ids[0]); answer.code != http.StatusNotFound {
		t.Errorf("DELETE an already-removed entry: got %d, want %d", answer.code, http.StatusNotFound)
	}
}

// Half a tracked span may not be removed as an entry.
//
// The pairing is POSITIONAL: the readers walk the node's entries forward holding one open start per
// user and close it with the next stop. Remove the stop alone and the start it closed is re-paired
// with a LATER stop — a session that silently grows to cover the gap, reported under a 200 nobody
// would think to check.
func TestDeleteEntryRefusesHalfOfATrackedSpan(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "time/site")

	for cycle := 0; cycle < 2; cycle++ {
		post(t, server.handleStartTimeTracking, userID, map[string]interface{}{"path": path})
		post(t, server.handleStopTimeTracking, userID, map[string]interface{}{"path": path})
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to reach %s: %v", path, err)
	}
	if len(node.Entries) != 4 {
		t.Fatalf("The fixture wrote %d entries, want 4", len(node.Entries))
	}

	for _, sentinel := range []int{0, 1} {
		answer := deleteEntry(t, server, userID, path, node.Entries[sentinel].ID)
		if answer.code != http.StatusConflict {
			t.Fatalf("DELETE entry %d of a tracked span: got %d, want %d", sentinel, answer.code, http.StatusConflict)
		}
		if !strings.Contains(answer.body, "/time/") {
			t.Errorf("The refusal does not name the route that removes a span: %s", answer.body)
		}
	}
	if len(node.Entries) != 4 {
		t.Errorf("A refused delete removed a sentinel anyway: %d entries left", len(node.Entries))
	}
	if spans := trackedSpans(t, server, userID, path); len(spans) != 2 {
		t.Errorf("The refusals disturbed the spans: %d reported, want 2", len(spans))
	}
}

// DELETE /time/{id} removes BOTH ends, and leaves the other spans measuring what they measured.
//
// The id is the START's, which is what GET /time and /query select=time report as the span's `id` —
// a span is not stored, so the entry that opens it is the only name it can have.
func TestDeleteTimeSpanRemovesBothEndsAndLeavesTheRestAlone(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "time/two")

	for cycle := 0; cycle < 2; cycle++ {
		post(t, server.handleStartTimeTracking, userID, map[string]interface{}{"path": path})
		post(t, server.handleStopTimeTracking, userID, map[string]interface{}{"path": path})
	}

	before := trackedSpans(t, server, userID, path)
	if len(before) != 2 {
		t.Fatalf("The fixture reported %d spans, want 2", len(before))
	}
	survivor := before[1]

	answer := deleteTimeSpan(t, server, userID, path, before[0]["id"].(string))
	if answer.code != http.StatusOK {
		t.Fatalf("DELETE the first span: got %d: %s", answer.code, answer.body)
	}
	if !strings.Contains(answer.body, `"entries_removed":2`) {
		t.Errorf("The answer does not say both ends went: %s", answer.body)
	}

	after := trackedSpans(t, server, userID, path)
	if len(after) != 1 {
		t.Fatalf("Removing one of two spans left %d", len(after))
	}
	if after[0]["id"] != survivor["id"] {
		t.Errorf("The surviving span is %v, want %v", after[0]["id"], survivor["id"])
	}
	// THE DURATION IS THE ONE IT ALWAYS WAS. This is what removing one end alone would have broken:
	// the survivor would have been re-paired across the gap and reported a longer session.
	if after[0]["duration"] != survivor["duration"] {
		t.Errorf("The surviving span now measures %v, it measured %v",
			after[0]["duration"], survivor["duration"])
	}

	if len(publishedOfKind(server, mutationTimeSpanDeleted)) != 1 {
		t.Error("Removing a tracked span was not announced")
	}
	if spans := trackedSpans(t, reloadServer(t, dir), userID, path); len(spans) != 1 {
		t.Errorf("A restart reported %d spans, want 1", len(spans))
	}
}

// A running timer is cancellable, and an id that opens nothing is a 404.
func TestDeleteTimeSpanCancelsARunningTimerAndRefusesAnythingElse(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "time/running")

	var started map[string]interface{}
	decodeBody(t, post(t, server.handleStartTimeTracking, userID, map[string]interface{}{"path": path}), &started)
	spanID, named := started["id"].(string)
	if !named || spanID == "" {
		t.Fatalf("POST /time/start did not name the span it opened: %v", started)
	}

	answer := deleteTimeSpan(t, server, userID, path, spanID)
	if answer.code != http.StatusOK {
		t.Fatalf("Cancelling a running timer: got %d: %s", answer.code, answer.body)
	}
	if !strings.Contains(answer.body, `"entries_removed":1`) {
		t.Errorf("An unclosed span removed something other than its one entry: %s", answer.body)
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to reach %s: %v", path, err)
	}
	if len(node.Entries) != 0 {
		t.Errorf("The cancelled timer left %d entries behind", len(node.Entries))
	}

	// An id that names no span at all — and an id that names an ordinary entry — are both 404s
	// rather than partial removals of something.
	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "run"})
	post(t, server.handleAppendToEvent, userID, map[string]interface{}{
		"path": path, "event_id": "run", "content": "not a span",
	})
	ordinary := entriesOf(t, server, userID, path, "run")[0].ID

	for _, id := range []string{"entry-does-not-exist", ordinary} {
		if answer := deleteTimeSpan(t, server, userID, path, id); answer.code != http.StatusNotFound {
			t.Errorf("DELETE /time/%s: got %d, want %d", id, answer.code, http.StatusNotFound)
		}
	}
	if left := entriesOf(t, server, userID, path, "run"); len(left) != 1 {
		t.Errorf("A refused span delete removed an ordinary entry: %d left", len(left))
	}
}
