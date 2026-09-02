package internal

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/vaziolabs/lumberjack/types"
)

// THE DEFECT: POST /events/start answered 200 for an event that afterwards existed neither in the
// state file nor in memory. Reproducible when a client drove start/append/end/entries about 300ms
// apart, not at 500ms — which is the shape of a race, not of a rule.
//
// It was not in the API queue. Every mutating route held only the mutex of the single node it was
// changing, while writeChangesToFile marshalled the WHOLE forest under a different lock. Disjoint
// locks: json.Marshal read Children, Events, Users and Entries of every node while another request
// wrote into them. The Go runtime does not promise to catch that. When it catches it the process
// dies; when it does not, the insert in flight can be lost in the middle of a map grow — and both
// StartEvent and the persist had already returned nil, so the handler answered 200.
//
// These tests drive concurrent cycles hard enough to make it certain rather than likely. Against
// the pre-fix engine TestConcurrentEventCyclesAreDurable dies with
// "fatal error: concurrent map iteration and map write" on every run.

// reloadServer brings the state file back up the way a restart does.
func reloadServer(t *testing.T, dir string) *Server {
	t.Helper()

	loaded, err := LoadServer(types.ServerConfig{
		Organization: "test_org",
		Process: types.ProcessInfo{
			ID:           "stock_process",
			Name:         "stock",
			ServerURL:    "localhost",
			ServerPort:   "8080",
			LogPath:      dir,
			DatabasePath: dir,
		},
	})
	if err != nil {
		t.Fatalf("Failed to reload the database: %v", err)
	}
	return loaded
}

// An acknowledged event cycle is on disk, under concurrency.
//
// Every 200 from /events/start is a promise, and the promise is kept across a restart — which is
// the only place the difference between "in memory" and "persisted" can be seen.
func TestConcurrentEventCyclesAreDurable(t *testing.T) {
	dir := t.TempDir()
	server := newServerInDirs(t, dir, dir)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/durable")

	// 200 concurrent cycles against ONE node. The contention has to be on a single node's maps:
	// that is where the marshal and the mutation met.
	const cycles = 200

	var mutex sync.Mutex
	acknowledged := make(map[string]bool, cycles)

	var waiting sync.WaitGroup
	for cycle := 0; cycle < cycles; cycle++ {
		waiting.Add(1)
		go func(cycle int) {
			defer waiting.Done()

			eventID := fmt.Sprintf("cycle-%d", cycle)
			started := post(t, server.handleStartEvent, userID, map[string]interface{}{
				"path": path, "event_id": eventID,
			})
			if started.Code != http.StatusOK {
				return
			}

			mutex.Lock()
			acknowledged[eventID] = true
			mutex.Unlock()

			post(t, server.handleAppendToEvent, userID, map[string]interface{}{
				"path": path, "event_id": eventID, "content": "entry",
			})
			post(t, server.handleEndEvent, userID, map[string]interface{}{
				"path": path, "event_id": eventID,
			})
			post(t, server.handleGetEventEntries, userID, map[string]interface{}{
				"path": path, "event_id": eventID,
			})
		}(cycle)
	}
	waiting.Wait()

	if len(acknowledged) != cycles {
		t.Fatalf("Acknowledged %d of %d cycles: the fixture is not exercising the race", len(acknowledged), cycles)
	}

	live, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to read back the node: %v", err)
	}
	for eventID := range acknowledged {
		if _, exists := live.Events[eventID]; !exists {
			t.Fatalf("%s was acknowledged and is not in memory", eventID)
		}
	}

	restarted := reloadServer(t, dir)
	persisted, err := restarted.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to read back the node after a restart: %v", err)
	}

	for eventID := range acknowledged {
		event, exists := persisted.Events[eventID]
		if !exists {
			t.Fatalf("%s was acknowledged with 200 and is not in the state file", eventID)
		}
		if len(event.Entries) != 1 {
			t.Errorf("%s persisted %d entries, want 1", eventID, len(event.Entries))
		}
		if event.EndTime == nil {
			t.Errorf("%s persisted without the end that was acknowledged", eventID)
		}
	}
}

// Reading the forest while it is being changed is safe, and every read is a whole answer.
//
// GET /forest serialized the live graph with no lock at all, so it raced every mutating route the
// same way the persist did.
func TestForestReadsAreSafeUnderConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	server := newServerInDirs(t, dir, dir)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/read-under-write")

	var waiting sync.WaitGroup
	for writer := 0; writer < 50; writer++ {
		waiting.Add(1)
		go func(writer int) {
			defer waiting.Done()
			post(t, server.handleStartEvent, userID, map[string]interface{}{
				"path": path, "event_id": fmt.Sprintf("write-%d", writer),
			})
		}(writer)
	}

	for reader := 0; reader < 50; reader++ {
		waiting.Add(1)
		go func() {
			defer waiting.Done()
			if code := get(t, server.handleGetForest, userID, "/forest").Code; code != http.StatusOK {
				t.Errorf("GET /forest under concurrent writes: got %d, want %d", code, http.StatusOK)
			}
		}()
	}
	waiting.Wait()
}

// The unchanged-hash skip is an acknowledgment that the change is already on disk. It may not be
// given when the file is not there: an install whose data directory was cleared underneath it was
// told every write succeeded while nothing was ever written.
func TestPersistDoesNotSkipWhenTheStateFileIsGone(t *testing.T) {
	dir := t.TempDir()
	server := newServerInDirs(t, dir, dir)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/vanished")

	statePath := server.statePath()
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("The fixture never wrote a state file: %v", err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatalf("Failed to clear the state file: %v", err)
	}

	// A change whose serialized forest is byte-identical to the last one written: an event that
	// carries no timestamp of its own, planned at times the test fixes.
	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": path, "event_id": "after-the-clear",
	}).Code; code != http.StatusOK {
		t.Fatalf("Start event: got %d, want %d", code, http.StatusOK)
	}

	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("The state file was not rewritten after being cleared: %v", err)
	}

	// And the skip itself: persisting the very same forest twice must leave the file there.
	if err := server.persistState(statePath); err != nil {
		t.Fatalf("Second persist: %v", err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatalf("Failed to clear the state file again: %v", err)
	}
	if err := server.persistState(statePath); err != nil {
		t.Fatalf("Persist after the file was cleared: %v", err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("Persist reported success without writing anything: %v", err)
	}
}
