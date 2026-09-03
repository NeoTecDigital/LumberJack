package internal

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// DELETE /events/{id} and PATCH /events/{id}.
//
// A meeting could be planned and never cancelled, and moving one by a day meant re-sending the
// whole record through an upsert that REPLACES — so a call that omitted metadata cleared it. These
// tests are about the two things that made those routes non-trivial: which of the two event maps an
// id names, and the difference between merging a record and overwriting it.

// planned times, fixed so that a retime is checkable rather than approximately right.
const (
	plannedStart = "2026-09-05T09:00:00Z"
	plannedEnd   = "2026-09-05T10:00:00Z"
	movedStart   = "2026-09-06T14:00:00Z"
	movedEnd     = "2026-09-06T15:00:00Z"
)

// planAtFixedSpan puts a plan on a node at the times above.
//
// NOT api_plan_conflict_test.go's planEvent, which plans relative to now: a test that asserts a
// retime has to know what the times were before it, and "an hour from whenever the test ran" is not
// something an assertion can name. It also carries metadata, which is what the merge tests are
// about.
func planAtFixedSpan(t *testing.T, server *Server, userID, path, eventID string, metadata map[string]interface{}) {
	t.Helper()

	body := map[string]interface{}{
		"path": path, "event_id": eventID, "start_time": plannedStart, "end_time": plannedEnd,
	}
	if metadata != nil {
		body["metadata"] = metadata
	}
	if code := post(t, server.handlePlanEvent, userID, body).Code; code != http.StatusOK {
		t.Fatalf("Plan %s: got %d", eventID, code)
	}
}

// patchEvent drives PATCH /events/{id} and answers the status and the body.
func patchEvent(t *testing.T, server *Server, userID, path, eventID, kind string, patch map[string]interface{}) (int, map[string]interface{}) {
	t.Helper()

	target := "/events/" + eventID + "?path=" + path
	if kind != "" {
		target += "&kind=" + kind
	}

	recorder := serveRoute(t, server, "PATCH", target, userID, patch)
	answer := map[string]interface{}{}
	if recorder.Code == http.StatusOK {
		answered(t, recorder, &answer)
	}
	return recorder.Code, answer
}

// eventOf is the projected event out of a PATCH answer.
func eventOf(t *testing.T, answer map[string]interface{}) map[string]interface{} {
	t.Helper()

	event, ok := answer["event"].(map[string]interface{})
	if !ok {
		t.Fatalf("The answer carried no event: %v", answer)
	}
	return event
}

// An id in BOTH maps is refused, and the refusal names the parameter that resolves it.
//
// Planning an event and then starting it leaves the id in PlannedEvents AND in Events — the
// ordinary lifecycle, not a corner. Every reader flattens the two and lets the live one win, which
// is right for reading and wrong for a delete: "the live one wins" applied to a removal leaves the
// plan behind, still in GET /forest, under a 200 that said it was gone.
func TestDeleteEventRefusesAnAmbiguousIDAndSaysHowToResolveIt(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "cal/room")

	planAtFixedSpan(t, server, userID, path, "standup", nil)
	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": path, "event_id": "standup",
	}).Code; code != http.StatusOK {
		t.Fatalf("Start the planned event: got %d", code)
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to reach %s: %v", path, err)
	}
	if live, planned := node.HoldsEvent("standup"); !live || !planned {
		t.Fatalf("The fixture did not produce the ambiguity: live=%t planned=%t", live, planned)
	}

	recorder := serveRoute(t, server, "DELETE", "/events/standup?path="+path, userID, nil)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("DELETE an ambiguous event: got %d, want %d", recorder.Code, http.StatusConflict)
	}
	if !strings.Contains(recorder.Body.String(), "kind=") {
		t.Errorf("The refusal does not name the parameter that resolves it: %s", recorder.Body.String())
	}
	if live, planned := node.HoldsEvent("standup"); !live || !planned {
		t.Fatal("A refused delete removed one of them anyway")
	}

	// Named, it removes exactly the one that was named — and the ANSWER says which, so a caller is
	// never told "deleted" without being told what was deleted.
	var removed map[string]interface{}
	decodeBody(t, serveRoute(t, server, "DELETE", "/events/standup?path="+path+"&kind=planned", userID, nil), &removed)
	if removed["kind"] != eventKindPlanned {
		t.Errorf("The answer says kind %v, want %s", removed["kind"], eventKindPlanned)
	}
	if live, planned := node.HoldsEvent("standup"); !live || planned {
		t.Fatalf("kind=planned left live=%t planned=%t, want live=true planned=false", live, planned)
	}

	if code := serveRoute(t, server, "DELETE", "/events/standup?path="+path+"&kind=live", userID, nil).Code; code != http.StatusOK {
		t.Fatalf("DELETE kind=live: got %d", code)
	}
	if live, planned := node.HoldsEvent("standup"); live || planned {
		t.Error("The event is still on the node after both maps were cleared")
	}
}

// Deleting an event takes the entries inside it and the files hanging off them.
//
// An entry inside an event is addressable by nothing once the event is gone, so keeping it would be
// keeping bytes no route can ever return.
func TestDeleteEventRemovesWhatWasInsideItDurably(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "cal/site")

	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "shift"})
	for _, text := range []string{"one", "two"} {
		post(t, server.handleAppendToEvent, userID, map[string]interface{}{
			"path": path, "event_id": "shift", "content": text,
		})
	}

	var removed map[string]interface{}
	decodeBody(t, serveRoute(t, server, "DELETE", "/events/shift?path="+path, userID, nil), &removed)
	if removed["entries_removed"] != float64(2) {
		t.Errorf("The answer reports %v entries removed, want 2", removed["entries_removed"])
	}

	if code := post(t, server.handleGetEventEntries, userID, map[string]interface{}{
		"path": path, "event_id": "shift",
	}).Code; code == http.StatusOK {
		t.Error("The event still answers its entries after being deleted")
	}

	announced := publishedOfKind(server, mutationEventDeleted)
	if len(announced) != 1 || announced[0].EventID != "shift" {
		t.Fatalf("The stream announced %v, want one event_deleted naming shift", announced)
	}

	restarted := reloadServer(t, dir)
	node, err := restarted.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to reach %s after a restart: %v", path, err)
	}
	if live, planned := node.HoldsEvent("shift"); live || planned {
		t.Error("The event came back after a restart")
	}
}

// PATCH MERGES. The upsert it replaces overwrote the whole record.
//
// The measured behaviour of POST /events/plan is that a call omitting `metadata` clears it, so
// moving a meeting by a day meant re-sending everything the event carried or losing it. A patch
// changes what it names and nothing else — and a metadata key set to null is DELETED, which is the
// only way a merge can remove anything. That is the same rule PATCH /nodes/{path}/metadata follows.
func TestPatchEventMergesRatherThanReplacing(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "cal/merge")

	planAtFixedSpan(t, server, userID, path, "review", map[string]interface{}{"room": "east", "owner": "ada"})

	// A retime that says nothing about metadata leaves metadata alone.
	code, answer := patchEvent(t, server, userID, path, "review", "", map[string]interface{}{
		"start_time": movedStart, "end_time": movedEnd,
	})
	if code != http.StatusOK {
		t.Fatalf("PATCH a retime: got %d, want %d", code, http.StatusOK)
	}

	event := eventOf(t, answer)
	metadata, ok := event["metadata"].(map[string]interface{})
	if !ok || metadata["room"] != "east" || metadata["owner"] != "ada" {
		t.Fatalf("A retime that never mentioned metadata changed it: %v", event["metadata"])
	}
	if !movedTo(t, event["start_time"], movedStart) || !movedTo(t, event["end_time"], movedEnd) {
		t.Errorf("The event was not retimed: %v -> %v", event["start_time"], event["end_time"])
	}

	// A metadata patch merges key by key, and null removes.
	_, answer = patchEvent(t, server, userID, path, "review", "", map[string]interface{}{
		"metadata": map[string]interface{}{"room": nil, "seats": float64(8)},
	})
	metadata = eventOf(t, answer)["metadata"].(map[string]interface{})
	if _, present := metadata["room"]; present {
		t.Error("A key set to null was not removed")
	}
	if metadata["owner"] != "ada" {
		t.Error("A merge dropped a key the patch never mentioned")
	}
	if metadata["seats"] != float64(8) {
		t.Error("A merge did not add the key the patch carried")
	}
}

// movedTo reports whether a returned timestamp is the one that was asked for.
func movedTo(t *testing.T, got interface{}, want string) bool {
	t.Helper()

	text, ok := got.(string)
	if !ok {
		return false
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		t.Fatalf("The event carried a time that is not RFC3339: %q", text)
	}
	expected, err := time.Parse(time.RFC3339, want)
	if err != nil {
		t.Fatalf("The fixture time is not RFC3339: %q", want)
	}
	return parsed.Equal(expected)
}

// PATCH will not end a live event, and will not accept a span that runs backwards.
//
// Status is what /events/start and /events/end mean. A second way to move an event through its
// lifecycle is a second set of rules about when an end time may exist, and two sets of rules for one
// thing is how they come to disagree.
func TestPatchEventRefusesToEndALiveEvent(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "cal/live")

	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "shift"})

	recorder := serveRoute(t, server, "PATCH", "/events/shift?path="+path, userID, map[string]interface{}{
		"end_time": movedEnd,
	})
	if recorder.Code != http.StatusConflict {
		t.Fatalf("PATCH end_time onto an ongoing event: got %d, want %d", recorder.Code, http.StatusConflict)
	}
	if !strings.Contains(recorder.Body.String(), "/events/end") {
		t.Errorf("The refusal does not name the route that ends an event: %s", recorder.Body.String())
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to reach %s: %v", path, err)
	}
	if node.Events["shift"].EndTime != nil {
		t.Error("A refused patch ended the event anyway")
	}

	// A plan may be retimed freely, and a backwards span is refused wherever it is asked for.
	planAtFixedSpan(t, server, userID, path, "review", nil)
	if code, _ := patchEvent(t, server, userID, path, "review", "", map[string]interface{}{
		"start_time": movedEnd, "end_time": movedStart,
	}); code != http.StatusBadRequest {
		t.Errorf("PATCH with end before start: got %d, want %d", code, http.StatusBadRequest)
	}
}

// A rename moves the event to a new id, and the stream says what it used to be called.
//
// A client watching the old id has no other way to learn that the event it is following is the one
// that just appeared under a different name.
func TestPatchEventRenamesAndAnnouncesThePreviousID(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "cal/rename")

	planAtFixedSpan(t, server, userID, path, "draft", map[string]interface{}{"room": "east"})
	planAtFixedSpan(t, server, userID, path, "taken", nil)

	code, answer := patchEvent(t, server, userID, path, "draft", "", map[string]interface{}{
		"event_id": "quarterly-review",
	})
	if code != http.StatusOK {
		t.Fatalf("PATCH a rename: got %d, want %d", code, http.StatusOK)
	}
	if answer["event_id"] != "quarterly-review" {
		t.Errorf("The answer names %v, want quarterly-review", answer["event_id"])
	}

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to reach %s: %v", path, err)
	}
	if _, old := node.HoldsEvent("draft"); old {
		t.Error("The old id still names a plan after a rename")
	}
	if _, renamed := node.HoldsEvent("quarterly-review"); !renamed {
		t.Fatal("The new id names nothing after a rename")
	}
	if room := node.PlannedEvents["quarterly-review"].Metadata["room"]; room != "east" {
		t.Errorf("A rename lost the record it moved: room is %v, want east", room)
	}

	announced := publishedOfKind(server, mutationEventUpdated)
	if len(announced) != 1 {
		t.Fatalf("The stream announced %d updates for one patch", len(announced))
	}
	if announced[0].EventID != "quarterly-review" || announced[0].PreviousEventID != "draft" {
		t.Errorf("The stream announced %s (was %q), want quarterly-review (was draft)",
			announced[0].EventID, announced[0].PreviousEventID)
	}

	// A rename onto an id the node already uses is an OVERWRITE of somebody else's record wearing
	// a rename's name.
	if code, _ := patchEvent(t, server, userID, path, "quarterly-review", "", map[string]interface{}{
		"event_id": "taken",
	}); code != http.StatusConflict {
		t.Errorf("PATCH renaming onto a used id: got %d, want %d", code, http.StatusConflict)
	}
}

// The typed fields become settable, and setting them does not write metadata.
//
// Category, Frequency and Pattern were derived out of metadata keys by StartEvent and reachable by
// no route at all for a plan — measured from the frontend as "category cannot be set by any route".
// Here they are their own fields, and `metadata.category` stays a metadata key.
func TestPatchEventSetsTheTypedFieldsNoRouteCouldSet(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "cal/typed")

	planAtFixedSpan(t, server, userID, path, "weekly", nil)

	code, answer := patchEvent(t, server, userID, path, "weekly", "", map[string]interface{}{
		"category":  "inspection",
		"frequency": "weekly",
		"pattern":   "MON",
		"metadata":  map[string]interface{}{"category": "a metadata key, not the field"},
	})
	if code != http.StatusOK {
		t.Fatalf("PATCH the typed fields: got %d, want %d", code, http.StatusOK)
	}

	event := eventOf(t, answer)
	if event["category"] != "inspection" || event["frequency"] != "weekly" || event["pattern"] != "MON" {
		t.Errorf("The typed fields are %v/%v/%v, want inspection/weekly/MON",
			event["category"], event["frequency"], event["pattern"])
	}
	metadata := event["metadata"].(map[string]interface{})
	if metadata["category"] != "a metadata key, not the field" {
		t.Errorf("The metadata key was rewritten by the typed field: %v", metadata["category"])
	}
}
