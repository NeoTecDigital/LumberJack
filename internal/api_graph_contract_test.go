// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/internal/graph"
)

// The rules added to the graph contract after wave 1 QA, as a client meets them over HTTP. The
// engine's own tests (internal/graph/engine_test.go) hold the same rules against the forest.

// blockStateFile makes every flush fail until the returned function is called: a directory sits
// on the temp path every persist opens. It is the injection state_failure_test.go uses, made to
// LAST — a failed publish removes its temp path, which clears an empty directory and so unblocks
// the very next flush; one that holds a file is not removable that way.
func blockStateFile(t *testing.T, server *Server) func() {
	t.Helper()
	blocker := server.statePath() + ".tmp"
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatalf("occupy the temp path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blocker, "held"), nil, 0o600); err != nil {
		t.Fatalf("hold the temp path: %v", err)
	}
	return func() {
		if err := os.RemoveAll(blocker); err != nil {
			t.Fatalf("free the temp path: %v", err)
		}
	}
}

func graphErrorCodeOf(body map[string]interface{}) interface{} {
	failure, _ := body["error"].(map[string]interface{})
	return failure["code"]
}

// Item 4. A flush that fails answers 5xx and leaves the outcome unknown. Until a flush succeeds a
// NEW command is refused 503 and leaves nothing behind; the SAME command id is still taken, fails
// while the disk does, and converges — replayed, and on the disk — once it does not.
func TestGraphRefusesNewCommandsUntilAFailedFlushIsRetried(t *testing.T) {
	server, config := newGraphServer(t)
	token := graphAdmin(t, server)
	graphCall(t, server, token, "POST", "/graph/commands", graphSeed())

	unblock := blockStateFile(t, server)
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-1", 10, 1)); status != http.StatusInternalServerError {
		t.Fatalf("a command whose flush failed: %d %v", status, body)
	}
	status, body := graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-2", 20, 2))
	if status != http.StatusServiceUnavailable || graphErrorCodeOf(body) != "unavailable" {
		t.Fatalf("a new command while the forest is ahead of its file: %d %v", status, body)
	}
	// While the forest is ahead of its file the reads answer 503 too: a receipt held only in
	// memory is not shown, and neither is the absence of one. See readGraph.
	if status, body := graphCall(t, server, token, "GET", "/graph/commands/move-2", nil); status != http.StatusServiceUnavailable || graphErrorCodeOf(body) != "unavailable" {
		t.Fatalf("a receipt read while the forest is ahead of its file: %d %v", status, body)
	}
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-1", 10, 1)); status != http.StatusInternalServerError {
		t.Fatalf("the retry while the disk still fails: %d %v", status, body)
	}

	unblock()
	status, body = graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-1", 10, 1))
	if status != http.StatusOK || body["replayed"] != true || body["revision"].(float64) != 2 {
		t.Fatalf("the retry of the same command id did not converge: %d %v", status, body)
	}
	if status, _ := graphCall(t, server, token, "GET", "/graph/commands/move-2", nil); status != http.StatusNotFound {
		t.Fatalf("the refused command left a receipt: %d", status)
	}
	status, body = graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-2", 20, 2))
	if status != http.StatusOK || body["replayed"] != false || body["revision"].(float64) != 3 {
		t.Fatalf("a new command after the flush succeeded: %d %v", status, body)
	}

	server = reopenGraphServer(t, server, config)
	token = graphAdmin(t, server)
	if status, snapshot := graphCall(t, server, token, "GET", "/graph", nil); status != http.StatusOK || snapshot["revision"].(float64) != 3 {
		t.Fatalf("the disk after convergence: %d %v", status, snapshot)
	}
	if status, _ := graphCall(t, server, token, "GET", "/graph/commands/move-1", nil); status != http.StatusOK {
		t.Fatalf("the retried command's receipt is not on the disk: %d", status)
	}
}

// "Until a flush succeeds" is ANY flush: the forest is one snapshot, so a later write by another
// route publishes the command that failed, and the graph takes new commands again without waiting
// for a caller that may never come back.
func TestGraphTakesCommandsAgainOnceAnyFlushSucceeds(t *testing.T) {
	server, config := newGraphServer(t)
	token := graphAdmin(t, server)
	graphCall(t, server, token, "POST", "/graph/commands", graphSeed())

	unblock := blockStateFile(t, server)
	if status, _ := graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-1", 10, 1)); status != http.StatusInternalServerError {
		t.Fatalf("a command whose flush failed: %d", status)
	}
	unblock()
	if status, _ := graphCall(t, server, token, "POST", "/nodes", map[string]string{"path": "work/n", "type": "leaf"}); status != http.StatusOK {
		t.Fatalf("an ordinary write: %d", status)
	}
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-2", 20, 2)); status != http.StatusOK || body["revision"].(float64) != 3 {
		t.Fatalf("a new command after another route's flush: %d %v", status, body)
	}
	server = reopenGraphServer(t, server, config)
	if status, body := graphCall(t, server, graphAdmin(t, server), "POST", "/graph/commands", graphMove("move-1", 10, 1)); status != http.StatusOK || body["replayed"] != true {
		t.Fatalf("the command answered 500 was not on the disk after all: %d %v", status, body)
	}
}

// A caller that restarted no longer knows the id it was answered 5xx for, so it cannot retry it.
// Once the disk takes writes again a NEW command is enough: the forest is flushed as it stands
// before the engine sees the command, which puts the command that failed on the disk with it.
func TestGraphRecoversFromAFailedFlushOnANewCommand(t *testing.T) {
	server, config := newGraphServer(t)
	token := graphAdmin(t, server)
	graphCall(t, server, token, "POST", "/graph/commands", graphSeed())

	unblock := blockStateFile(t, server)
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-1", 10, 1)); status != http.StatusInternalServerError {
		t.Fatalf("a command whose flush failed: %d %v", status, body)
	}
	unblock()
	status, body := graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-2", 20, 2))
	if status != http.StatusOK || body["replayed"] != false || body["revision"].(float64) != 3 {
		t.Fatalf("a new command once the disk recovered: %d %v", status, body)
	}

	server = reopenGraphServer(t, server, config)
	token = graphAdmin(t, server)
	if status, snapshot := graphCall(t, server, token, "GET", "/graph", nil); status != http.StatusOK || snapshot["revision"].(float64) != 3 {
		t.Fatalf("the disk after recovery: %d %v", status, snapshot)
	}
	status, body = graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-1", 10, 1))
	if status != http.StatusOK || body["replayed"] != true || body["revision"].(float64) != 2 {
		t.Fatalf("the command answered 500 is not on the disk: %d %v", status, body)
	}
}

// Item 3, over HTTP: 400, naming both ids, and nothing stored.
func TestGraphRefusesAValueIDThatDiffersFromTheOperationID(t *testing.T) {
	server, _ := newGraphServer(t)
	token := graphAdmin(t, server)
	other := strings.Repeat("3", 64)
	cmd := map[string]interface{}{"id": "forged", "fingerprint": "forged", "expected": map[string]interface{}{"entities": map[string]uint64{graphTask: 0}},
		"operations": []interface{}{graphPut("entities", graphTask, graphEntity(other, "task"))}}
	status, body := graphCall(t, server, token, "POST", "/graph/commands", cmd)
	message, _ := body["error"].(map[string]interface{})["message"].(string)
	if status != http.StatusBadRequest || graphErrorCodeOf(body) != "invalid_command" || !strings.Contains(message, other) || !strings.Contains(message, graphTask) {
		t.Fatalf("a value.id that differs from the operation id: %d %v", status, body)
	}
	if status, snapshot := graphCall(t, server, token, "GET", "/graph", nil); status != http.StatusOK || len(snapshot["entities"].(map[string]interface{})) != 0 {
		t.Fatalf("the refused put stored something: %d %v", status, snapshot)
	}
}

// Item 5, over HTTP: a command that names no actor replays for whichever session retries it.
func TestGraphReplaysAnUnnamedActorAcrossSessions(t *testing.T) {
	server, _ := newGraphServer(t)
	token := graphAdmin(t, server)
	graphCall(t, server, token, "POST", "/graph/commands", graphSeed())
	second := addGraphMember(t, server, "second")
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-1", 10, 1)); status != http.StatusOK || body["replayed"] != false {
		t.Fatalf("first: %d %v", status, body)
	}
	if status, body := graphCall(t, server, second, "POST", "/graph/commands", graphMove("move-1", 10, 1)); status != http.StatusOK || body["replayed"] != true {
		t.Fatalf("the same body under another session's default actor: %d %v", status, body)
	}
	named := graphMove("move-1", 10, 1)
	named["actor"] = "agent:other"
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", named); status != http.StatusConflict {
		t.Fatalf("the same id with a different supplied actor: %d %v", status, body)
	}
}

// Item 6, over HTTP: the two fields are not accepted, and no answer carries them.
func TestGraphAcceptsNoOutOfContractFields(t *testing.T) {
	server, _ := newGraphServer(t)
	token := graphAdmin(t, server)
	for field, value := range map[string]interface{}{"client_fingerprint": "x", "result_metadata": map[string]string{"a": "b"}} {
		cmd := graphSeed()
		cmd[field] = value
		if status, body := graphCall(t, server, token, "POST", "/graph/commands", cmd); status != http.StatusBadRequest || graphErrorCodeOf(body) != "invalid_command" {
			t.Fatalf("a command carrying %s: %d %v", field, status, body)
		}
	}
	if status, snapshot := graphCall(t, server, token, "GET", "/graph", nil); status != http.StatusOK || snapshot["revision"].(float64) != 0 {
		t.Fatalf("a refused command was applied: %d %v", status, snapshot)
	}
	_, result := graphCall(t, server, token, "POST", "/graph/commands", graphSeed())
	_, receipt := graphCall(t, server, token, "GET", "/graph/commands/seed", nil)
	for _, answer := range []map[string]interface{}{result, receipt, receipt["result"].(map[string]interface{})} {
		if _, carried := answer["client_fingerprint"]; carried {
			t.Fatalf("an answer carries client_fingerprint: %v", answer)
		}
		if _, carried := answer["result_metadata"]; carried {
			t.Fatalf("an answer carries result_metadata: %v", answer)
		}
	}
}

// Item 2, over HTTP: a deleted record is in no collection of GET /graph, the 409 for treating its
// id as new names the revision its tombstone kept, and a re-creation continues from it.
func TestGraphTombstonesAreNotReportedAndContinueTheRevision(t *testing.T) {
	server, config := newGraphServer(t)
	token := graphAdmin(t, server)
	graphCall(t, server, token, "POST", "/graph/commands", graphSeed())
	gone := map[string]interface{}{"id": "gone", "fingerprint": "gone",
		"expected": map[string]interface{}{"entities": map[string]uint64{graphTask: 1}, "occurrences": map[string]uint64{graphOcc: 1}, "topology": map[string]uint64{graphScope: 1}},
		"operations": []interface{}{map[string]string{"op": "delete", "collection": "occurrences", "id": graphOcc},
			map[string]string{"op": "delete", "collection": "entities", "id": graphTask}}}
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", gone); status != http.StatusOK {
		t.Fatalf("delete: %d %v", status, body)
	}
	server = reopenGraphServer(t, server, config)
	token = graphAdmin(t, server)
	status, snapshot := graphCall(t, server, token, "GET", "/graph", nil)
	if status != http.StatusOK || len(snapshot["entities"].(map[string]interface{})) != 1 || len(snapshot["occurrences"].(map[string]interface{})) != 0 || len(snapshot) != 6 {
		t.Fatalf("a tombstone is reported by GET /graph: %d %v", status, snapshot)
	}
	back := func(id string, expected uint64, kind string) (int, map[string]interface{}) {
		return graphCall(t, server, token, "POST", "/graph/commands", map[string]interface{}{"id": id, "fingerprint": id,
			"expected":   map[string]interface{}{"entities": map[string]uint64{graphTask: expected}},
			"operations": []interface{}{graphPut("entities", graphTask, graphEntity(graphTask, kind))}})
	}
	status, body := back("as-new", 0, "task")
	failure, _ := body["error"].(map[string]interface{})
	if status != http.StatusConflict || failure["expected"].(float64) != 0 || failure["actual"].(float64) != 1 {
		t.Fatalf("a deleted id treated as new: %d %v", status, body)
	}
	if status, body := back("rekind", 1, "note"); status != http.StatusBadRequest {
		t.Fatalf("a deleted id back as another kind: %d %v", status, body)
	}
	status, body = back("back", 1, "task")
	if status != http.StatusOK || body["changes"].([]interface{})[0].(map[string]interface{})["revision"].(float64) != 2 {
		t.Fatalf("re-creation: %d %v", status, body)
	}
	if status, body := back("stale", 1, "task"); status != http.StatusConflict {
		t.Fatalf("a writer that last saw revision 1: %d %v", status, body)
	}
}

// addGraphMember makes an account that may command the graph, and answers its session.
func addGraphMember(t *testing.T, server *Server, username string) string {
	t.Helper()
	id := addReadUser(t, server, username)
	if err := graph.Root(server.forest).AssignUser(core.User{ID: id, Username: username}, core.WritePermission); err != nil {
		t.Fatal(err)
	}
	return sessionFor(t, server, id, username)
}
