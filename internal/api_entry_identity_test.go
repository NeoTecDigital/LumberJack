package internal

import (
	"net/http"
	"strings"
	"testing"
)

// ENTRY IDENTITY. An entry used to be addressed by (node_path, event_id, entry_index) and by
// nothing else, and an index is invalidated by every insertion and every deletion before it — so
// two clients holding one address held it for two different entries the moment anything was
// removed. These tests are about the property that replaces it: a name that does not move.

// entriesOf reads the entries of one event back through the route that returns them.
func entriesOf(t *testing.T, server *Server, userID, path, eventID string) []entryView {
	t.Helper()

	recorder := post(t, server.handleGetEventEntries, userID, map[string]interface{}{
		"path": path, "event_id": eventID,
	})
	var entries []entryView
	decodeBody(t, recorder, &entries)
	return entries
}

// idsOf is the ids of a run of entries, in order.
func idsOf(entries []entryView) []string {
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.ID)
	}
	return ids
}

// An entry's id survives what an index does not: an insertion, a deletion, and a restart.
//
// THE DEFECT: there was no id at all. The index that stood in for one is a POSITION, and deleting
// the entry in front of one moves it — so a client holding "entry 2 of this event" was, after one
// removal, holding a different entry, and a delete keyed on that address removed whatever had slid
// into the slot.
func TestEntryIDsSurviveAnInsertionADeletionAndARestart(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "msg/thread")

	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "run"})
	for _, text := range []string{"first", "second", "third"} {
		if code := post(t, server.handleAppendToEvent, userID, map[string]interface{}{
			"path": path, "event_id": "run", "content": text,
		}).Code; code != http.StatusOK {
			t.Fatalf("Append %s: got %d", text, code)
		}
	}

	original := idsOf(entriesOf(t, server, userID, path, "run"))
	if len(original) != 3 {
		t.Fatalf("Appended three entries and read back %d", len(original))
	}
	unique := map[string]bool{}
	for _, id := range original {
		if id == "" {
			t.Fatal("An entry came back with no id: an entry that cannot be named cannot be deleted")
		}
		unique[id] = true
	}
	if len(unique) != 3 {
		t.Fatalf("Three entries carry %d distinct ids: %v", len(unique), original)
	}

	// AN INSERTION. Nothing that already existed is renamed by something arriving after it.
	post(t, server.handleAppendToEvent, userID, map[string]interface{}{
		"path": path, "event_id": "run", "content": "fourth",
	})
	afterInsert := idsOf(entriesOf(t, server, userID, path, "run"))
	for index, id := range original {
		if afterInsert[index] != id {
			t.Errorf("Entry %d was %s before an append and %s after", index, id, afterInsert[index])
		}
	}

	// A DELETION, of the entry in FRONT. Every id behind it is unchanged while every index moved,
	// which is the whole difference between a name and a position.
	if code := serveRoute(t, server, "DELETE", "/entries/"+original[0]+"?path="+path, userID, nil).Code; code != http.StatusOK {
		t.Fatalf("DELETE /entries/%s: got %d", original[0], code)
	}
	afterDelete := entriesOf(t, server, userID, path, "run")
	if len(afterDelete) != 3 {
		t.Fatalf("Deleting one of four entries left %d", len(afterDelete))
	}
	if afterDelete[0].ID != original[1] {
		t.Errorf("The entry now at index 0 is %s, want %s: an id followed its position",
			afterDelete[0].ID, original[1])
	}
	if afterDelete[0].Content != "second" {
		t.Errorf("The entry now at index 0 says %v, want second", afterDelete[0].Content)
	}

	// A RESTART. The ids are in the state file, not in this process.
	restarted := reloadServer(t, dir)
	persisted := idsOf(entriesOf(t, restarted, userID, path, "run"))
	if len(persisted) != 3 {
		t.Fatalf("A restart read back %d entries, want 3", len(persisted))
	}
	for index, id := range idsOf(afterDelete) {
		if persisted[index] != id {
			t.Errorf("Entry %d was %s before a restart and %s after", index, id, persisted[index])
		}
	}
}

// Entries written before Entry.ID existed are named at load, and named the SAME WAY on every load.
//
// A freshly generated id would satisfy "every entry has an id" and fail the thing an id is for: an
// install that is read from and restarted without a mutation would hand out a permalink that
// resolves to nothing after the next start, and two processes reading one file would disagree about
// what an entry is called. The id is therefore derived from the position the file already records.
func TestEntriesWrittenBeforeIdentityGetTheSameIDOnEveryLoad(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "legacy/site")

	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "shift"})
	post(t, server.handleAppendToEvent, userID, map[string]interface{}{
		"path": path, "event_id": "shift", "content": "written before ids existed",
	})
	post(t, server.handleStartTimeTracking, userID, map[string]interface{}{"path": path})
	post(t, server.handleStopTimeTracking, userID, map[string]interface{}{"path": path})

	// A state file as an older build wrote one: every entry present, none of them named.
	blankEntryIDs(t, server, path)
	if err := server.persistState(server.statePath()); err != nil {
		t.Fatalf("Failed to write the state file: %v", err)
	}

	first := loadedEntryIDs(t, dir, path)
	if len(first) != 3 {
		t.Fatalf("The fixture wrote %d entries, want 3 (one in an event, two time sentinels)", len(first))
	}
	for _, id := range first {
		if id == "" {
			t.Fatal("An entry from an old state file was left with no id: no route can address it")
		}
		if !strings.HasPrefix(id, legacyEntryIDPrefixForTest) {
			t.Errorf("A backfilled id is %q, which does not say it was derived rather than minted", id)
		}
	}

	second := loadedEntryIDs(t, dir, path)
	for index, id := range first {
		if second[index] != id {
			t.Errorf("Entry %d was named %s on one load and %s on the next: the id is not an identity",
				index, id, second[index])
		}
	}
}

// legacyEntryIDPrefixForTest is the prefix a derived id carries. Restated here on purpose: a test
// that reads the constant it is checking cannot tell the constant changing from the behaviour
// changing, and this prefix is part of what an operator reading a state file is promised.
const legacyEntryIDPrefixForTest = "entry-legacy-"

// blankEntryIDs strips the ids off every entry on a node, the way a file written before the field
// existed carries them.
func blankEntryIDs(t *testing.T, server *Server, path string) {
	t.Helper()

	server.forestMutex.Lock()
	defer server.forestMutex.Unlock()

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to reach %s: %v", path, err)
	}
	for index := range node.Entries {
		node.Entries[index].ID = ""
	}
	for eventID, event := range node.Events {
		for index := range event.Entries {
			event.Entries[index].ID = ""
		}
		node.Events[eventID] = event
	}
}

// loadedEntryIDs restarts from the state file and reports every entry id on a node, in a fixed
// order: the node's own entries, then the entries of each event by id.
func loadedEntryIDs(t *testing.T, dir, path string) []string {
	t.Helper()

	server := reloadServer(t, dir)
	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to reach %s after a reload: %v", path, err)
	}

	ids := []string{}
	for _, entry := range node.Entries {
		ids = append(ids, entry.ID)
	}
	for _, eventID := range sortedEventIDs(node.Events) {
		for _, entry := range node.Events[eventID].Entries {
			ids = append(ids, entry.ID)
		}
	}
	return ids
}

// Every route that returns an entry returns its id, and every route that returns a tracked span
// returns the id that span is deleted by.
//
// A name that only one route knows is not an identity. The messenger reads entries through
// POST /events, the feed reads them through GET /entries, the canvas reads them inside GET /forest,
// and the calendar reads spans through GET /time — an id missing from any one of them is a screen
// that can render an entry it cannot act on.
func TestEveryRouteThatReturnsAnEntryNamesIt(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "named/site")

	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "run"})
	post(t, server.handleAppendToEvent, userID, map[string]interface{}{
		"path": path, "event_id": "run", "content": "hello",
	})
	post(t, server.handleStartTimeTracking, userID, map[string]interface{}{"path": path})
	post(t, server.handleStopTimeTracking, userID, map[string]interface{}{"path": path})

	if id := entriesOf(t, server, userID, path, "run")[0].ID; id == "" {
		t.Error("POST /events returned an entry with no id")
	}

	var feed queryResponse
	decodeBody(t, serveRoute(t, server, "GET", "/entries?scope=named", userID, nil), &feed)
	if len(feed.Results) == 0 {
		t.Fatal("GET /entries returned nothing to check")
	}
	for _, result := range feed.Results {
		if id := result.(map[string]interface{})["id"]; id == nil || id == "" {
			t.Errorf("GET /entries returned an entry with no id: %v", result)
		}
	}

	var forest nodeView
	decodeBody(t, get(t, server.handleGetForest, userID, "/forest"), &forest)
	for _, entry := range entriesUnder(forest) {
		if entry.ID == "" {
			t.Error("GET /forest returned an entry with no id")
		}
	}

	var spans []map[string]interface{}
	decodeBody(t, get(t, server.handleGetTimeTracking, userID, "/time?scope="+path), &spans)
	if len(spans) != 1 {
		t.Fatalf("GET /time reported %d spans, want 1", len(spans))
	}
	if id, named := spans[0]["id"]; !named || id == "" {
		t.Error("GET /time reported a span with no id: there is nothing DELETE /time/{id} could take")
	}
}

// entriesUnder is every entry in a projected forest, at any depth.
func entriesUnder(view nodeView) []entryView {
	entries := append([]entryView{}, view.Entries...)
	for _, event := range view.Events {
		entries = append(entries, event.Entries...)
	}
	for _, child := range view.Children {
		entries = append(entries, entriesUnder(child)...)
	}
	return entries
}
