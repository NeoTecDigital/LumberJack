// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/types"
)

// reopenGraphServer shuts the server down and loads the same state file again, the way a restart
// does. The caller's session does not survive — it mints a new one.
func reopenGraphServer(t *testing.T, server *Server, config types.ServerConfig) *Server {
	t.Helper()
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadServer(config)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Shutdown(context.Background()) })
	return reopened
}

func TestGraphReplaySurvivesReopen(t *testing.T) {
	server, config := newGraphServer(t)
	token := graphAdmin(t, server)
	graphCall(t, server, token, "POST", "/graph/commands", graphSeed())
	cmd := graphMove("move-1", 2500, 1)
	status, first := graphCall(t, server, token, "POST", "/graph/commands", cmd)
	if status != http.StatusOK || first["replayed"] != false || first["revision"].(float64) != 2 {
		t.Fatalf("first: %d %v", status, first)
	}
	status, second := graphCall(t, server, token, "POST", "/graph/commands", cmd)
	if status != http.StatusOK || second["replayed"] != true || second["revision"].(float64) != 2 || len(second["changes"].([]interface{})) != 1 {
		t.Fatalf("replay: %d %v", status, second)
	}

	server = reopenGraphServer(t, server, config)
	token = graphAdmin(t, server)
	status, receipt := graphCall(t, server, token, "GET", "/graph/commands/move-1", nil)
	if status != http.StatusOK || receipt["fingerprint"] != "move-1" || receipt["payload_digest"] == "" {
		t.Fatalf("durable receipt: %d %v", status, receipt)
	}
	status, replay := graphCall(t, server, token, "POST", "/graph/commands", cmd)
	if status != http.StatusOK || replay["replayed"] != true || replay["revision"].(float64) != 2 {
		t.Fatalf("replay after reopen: %d %v", status, replay)
	}
	if status, snapshot := graphCall(t, server, token, "GET", "/graph", nil); status != http.StatusOK || snapshot["revision"].(float64) != 2 {
		t.Fatalf("snapshot after reopen: %d %v", status, snapshot)
	}
}

func TestGraphEventsPageAndSurviveReopen(t *testing.T) {
	server, config := newGraphServer(t)
	token := graphAdmin(t, server)
	graphCall(t, server, token, "POST", "/graph/commands", graphSeed())
	graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-a", 1, 1))
	graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-b", 2, 2))

	status, page := graphCall(t, server, token, "GET", "/graph/events?since=0&limit=2", nil)
	if status != http.StatusOK || len(page["events"].([]interface{})) != 2 || page["next"].(float64) != 2 {
		t.Fatalf("first page: %d %v", status, page)
	}
	status, rest := graphCall(t, server, token, "GET", "/graph/events?since=2", nil)
	events := rest["events"].([]interface{})
	if status != http.StatusOK || len(events) != 1 || rest["next"] != nil || events[0].(map[string]interface{})["command_id"] != "move-b" {
		t.Fatalf("last page: %d %v", status, rest)
	}
	if status, _ := graphCall(t, server, token, "GET", "/graph/events?since=x", nil); status != http.StatusBadRequest {
		t.Fatalf("bad since: %d", status)
	}

	server = reopenGraphServer(t, server, config)
	token = graphAdmin(t, server)
	status, all := graphCall(t, server, token, "GET", "/graph/events", nil)
	events = all["events"].([]interface{})
	if status != http.StatusOK || len(events) != 3 {
		t.Fatalf("journal after reopen: %d %v", status, all)
	}
	seed := events[0].(map[string]interface{})
	if seed["revision"].(float64) != 1 || seed["actor"] != "agent:seed" || len(seed["changes"].([]interface{})) != 3 || seed["at"] == "" {
		t.Fatalf("seed event lost detail: %v", seed)
	}
}

func TestGraphDataDirectoryHoldsOnlyTheStateFile(t *testing.T) {
	server, config := newGraphServer(t)
	token := graphAdmin(t, server)
	before := dataDirListing(t, config.Process.DatabasePath)
	graphCall(t, server, token, "POST", "/graph/commands", graphSeed())
	graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-a", 1, 1))
	after := dataDirListing(t, config.Process.DatabasePath)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("graph commands added files: %v -> %v", before, after)
	}
	state := StatePath(config)
	for _, name := range after {
		if path := filepath.Join(config.Process.DatabasePath, name); path != state && path != StateLockPath(state) {
			t.Fatalf("unexpected file %q beside the state file", name)
		}
	}
}

func dataDirListing(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func TestGraphCommitsTwoThousandEntities(t *testing.T) {
	server, _ := newGraphServer(t)
	token := graphAdmin(t, server)
	const count = 2000
	expected := map[string]uint64{}
	operations := make([]interface{}, 0, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("%064x", 0x1000+i)
		expected[id] = 0
		operations = append(operations, graphPut("entities", id, map[string]interface{}{"id": id, "kind": "task", "title": fmt.Sprintf("Task %d", i)}))
	}
	cmd := map[string]interface{}{"id": "bulk", "fingerprint": "bulk", "expected": map[string]interface{}{"entities": expected}, "operations": operations}
	started := time.Now()
	status, result := graphCall(t, server, token, "POST", "/graph/commands", cmd)
	elapsed := time.Since(started)
	if status != http.StatusOK || len(result["changes"].([]interface{})) != count {
		t.Fatalf("bulk commit: %d %v", status, result)
	}
	t.Logf("committed %d entities in one command in %s (durable)", count, elapsed)
	status, snapshot := graphCall(t, server, token, "GET", "/graph", nil)
	if status != http.StatusOK || len(snapshot["entities"].(map[string]interface{})) != count {
		t.Fatalf("snapshot after bulk commit: %d entities", len(snapshot["entities"].(map[string]interface{})))
	}
	started = time.Now()
	one := fmt.Sprintf("%064x", 0x1000)
	follow := map[string]interface{}{"id": "one-more", "fingerprint": "one-more", "expected": map[string]interface{}{"entities": map[string]uint64{one: 1}},
		"operations": []interface{}{graphPut("entities", one, map[string]interface{}{"id": one, "kind": "task", "title": "Renamed"})}}
	if status, _ := graphCall(t, server, token, "POST", "/graph/commands", follow); status != http.StatusOK {
		t.Fatalf("follow-up commit: %d", status)
	}
	t.Logf("one-entity command over a %d-entity graph in %s (durable)", count, time.Since(started))
}
