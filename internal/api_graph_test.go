// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/internal/graph"
	"github.com/NeoTecDigital/LumberJack/types"
)

const (
	graphScope = "1111111111111111111111111111111111111111111111111111111111111111"
	graphTask  = "2222222222222222222222222222222222222222222222222222222222222222"
	graphOcc   = "4444444444444444444444444444444444444444444444444444444444444444"
)

// graphConfig is a fresh install whose state and logs live in directories the test chose.
func graphConfig(dataDir, logDir string) types.ServerConfig {
	return types.ServerConfig{Organization: "test_org", Process: types.ProcessInfo{
		ID: "graph_process", Name: "graph", ServerURL: "localhost", ServerPort: "8080", LogPath: logDir, DatabasePath: dataDir}}
}

func newGraphServer(t *testing.T) (*Server, types.ServerConfig) {
	t.Helper()
	config := graphConfig(t.TempDir(), t.TempDir())
	server, err := NewServer(config, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	return server, config
}

func graphAdmin(t *testing.T, server *Server) string {
	t.Helper()
	for _, user := range server.forest.Users {
		if user.Username == "admin" {
			return sessionFor(t, server, user.ID, user.Username)
		}
	}
	t.Fatal("no admin account")
	return ""
}

// graphCall sends a request through the MAIN router, session and all.
func graphCall(t *testing.T, server *Server, token, method, target string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		encoded, _ := json.Marshal(body)
		reader = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, target, reader)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, request)
	var decoded map[string]interface{}
	_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)
	return recorder.Code, decoded
}

func graphEntity(id, kind string) map[string]interface{} {
	return map[string]interface{}{"id": id, "kind": kind}
}

func graphOccurrence(x int64) map[string]interface{} {
	return map[string]interface{}{"id": graphOcc, "entity_id": graphTask, "scope_id": graphScope,
		"geometry": map[string]int64{"x": x, "y": 0, "width": 1000, "height": 1000, "scale": 1000000}}
}

func graphPut(collection, id string, value interface{}) map[string]interface{} {
	return map[string]interface{}{"op": "put", "collection": collection, "id": id, "value": value}
}

func graphSeed() map[string]interface{} {
	return map[string]interface{}{"id": "seed", "fingerprint": "seed-v1", "actor": "agent:seed",
		"expected": map[string]interface{}{"entities": map[string]uint64{graphScope: 0, graphTask: 0}, "occurrences": map[string]uint64{graphOcc: 0}, "topology": map[string]uint64{graphScope: 0}},
		"operations": []interface{}{
			graphPut("entities", graphScope, graphEntity(graphScope, "scope")),
			graphPut("entities", graphTask, graphEntity(graphTask, "task")),
			graphPut("occurrences", graphOcc, graphOccurrence(0)),
		}}
}

func graphMove(id string, x int64, occurrenceRevision uint64) map[string]interface{} {
	return map[string]interface{}{"id": id, "fingerprint": id,
		"expected":   map[string]interface{}{"occurrences": map[string]uint64{graphOcc: occurrenceRevision}, "topology": map[string]uint64{graphScope: 1}},
		"operations": []interface{}{graphPut("occurrences", graphOcc, graphOccurrence(x))}}
}

func TestGraphRoutesRequireSessionAndPermission(t *testing.T) {
	server, _ := newGraphServer(t)
	server.forest.Users = append(server.forest.Users, core.User{ID: "nobody", Username: "nobody"})
	reader := addReadUser(t, server, "reader")
	admin, nobody, readerToken := graphAdmin(t, server), sessionFor(t, server, "nobody", "nobody"), sessionFor(t, server, reader, "reader")
	for _, route := range []struct{ method, target string }{{"GET", "/graph"}, {"GET", "/graph/events"}, {"POST", "/graph/commands"}, {"GET", "/graph/commands/seed"}} {
		if status, _ := graphCall(t, server, "", route.method, route.target, graphSeed()); status != http.StatusUnauthorized {
			t.Fatalf("%s %s without a session: %d", route.method, route.target, status)
		}
	}
	if status, body := graphCall(t, server, admin, "POST", "/graph/commands", graphSeed()); status != http.StatusOK || body["revision"].(float64) != 1 {
		t.Fatalf("seed: %d %v", status, body)
	}
	if status, _ := graphCall(t, server, nobody, "GET", "/graph", nil); status != http.StatusForbidden {
		t.Fatalf("unpermitted read: %d", status)
	}
	if status, _ := graphCall(t, server, nobody, "POST", "/graph/commands", graphMove("m", 1, 1)); status != http.StatusForbidden {
		t.Fatalf("unpermitted write: %d", status)
	}
	if status, _ := graphCall(t, server, readerToken, "POST", "/graph/commands", graphMove("m", 1, 1)); status != http.StatusForbidden {
		t.Fatalf("reader write: %d", status)
	}
	if status, body := graphCall(t, server, readerToken, "GET", "/graph/commands/seed", nil); status != http.StatusOK || body["fingerprint"] != "seed-v1" {
		t.Fatalf("reader receipt: %d %v", status, body)
	}
	if status, body := graphCall(t, server, readerToken, "GET", "/graph", nil); status != http.StatusOK || len(body["entities"].(map[string]interface{})) != 2 {
		t.Fatalf("reader snapshot: %d %v", status, body)
	}
	if status, _ := graphCall(t, server, admin, "GET", "/graph/commands/missing", nil); status != http.StatusNotFound {
		t.Fatalf("missing receipt: %d", status)
	}
}

func TestGraphApplicationCallRoundTrip(t *testing.T) {
	server, _ := newGraphServer(t)
	token := graphAdmin(t, server)
	encoded, _ := json.Marshal(graphSeed())
	headers := map[string]string{"Authorization": "Bearer " + token}
	committed := server.ApplicationCall(ApplicationRequest{Method: "POST", Target: "/graph/commands", Headers: headers, Body: encoded})
	if committed.Status != http.StatusOK {
		t.Fatalf("commit: %d %s", committed.Status, committed.Body)
	}
	read := server.ApplicationCall(ApplicationRequest{Method: "GET", Target: "/graph", Headers: headers})
	var snapshot graph.Snapshot
	if read.Status != http.StatusOK || json.Unmarshal(read.Body, &snapshot) != nil {
		t.Fatalf("read: %d %s", read.Status, read.Body)
	}
	if snapshot.Revision != 1 || len(snapshot.Entities) != 2 || string(snapshot.Occurrences[graphOcc]["revision"]) != "1" {
		t.Fatalf("round trip lost state: %+v", snapshot)
	}
	events := server.ApplicationCall(ApplicationRequest{Method: "GET", Target: "/graph/events?since=0", Headers: headers})
	if events.Status != http.StatusOK || !bytes.Contains(events.Body, []byte(`"actor":"agent:seed"`)) {
		t.Fatalf("events: %d %s", events.Status, events.Body)
	}
}

func TestGraphInvalidBatchLeavesStateUnchanged(t *testing.T) {
	server, _ := newGraphServer(t)
	token := graphAdmin(t, server)
	graphCall(t, server, token, "POST", "/graph/commands", graphSeed())
	before, _ := encodeState(server.forest)
	bad := graphMove("bad", 0, 1)
	bad["operations"] = []interface{}{graphPut("occurrences", graphOcc, map[string]interface{}{"id": graphOcc, "entity_id": graphTask, "scope_id": graphScope,
		"geometry": map[string]interface{}{"x": 1.5, "y": 0, "width": 1, "height": 1, "scale": 1}})}
	status, body := graphCall(t, server, token, "POST", "/graph/commands", bad)
	if status != http.StatusBadRequest || body["error"].(map[string]interface{})["code"] != "invalid_command" {
		t.Fatalf("invalid batch: %d %v", status, body)
	}
	after, _ := encodeState(server.forest)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid batch changed the forest")
	}
	if status, _ := graphCall(t, server, token, "GET", "/graph/commands/bad", nil); status != http.StatusNotFound {
		t.Fatalf("invalid batch left a receipt: %d", status)
	}
}

func TestGraphStaleRevisionAnswers409WithDetails(t *testing.T) {
	server, _ := newGraphServer(t)
	token := graphAdmin(t, server)
	graphCall(t, server, token, "POST", "/graph/commands", graphSeed())
	status, body := graphCall(t, server, token, "POST", "/graph/commands", graphMove("stale", 1, 0))
	if status != http.StatusConflict {
		t.Fatalf("stale revision: %d %v", status, body)
	}
	failure := body["error"].(map[string]interface{})
	if failure["code"] != "conflict" || failure["collection"] != "occurrences" || failure["id"] != graphOcc || failure["expected"].(float64) != 0 || failure["actual"].(float64) != 1 {
		t.Fatalf("409 does not name the disagreement: %v", failure)
	}
	reused := graphSeed()
	reused["fingerprint"] = "seed-v2"
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", reused); status != http.StatusConflict || body["error"].(map[string]interface{})["collection"] != "commands" {
		t.Fatalf("reused id: %d %v", status, body)
	}
}

func TestGraphConcurrentStaleMutationHasOneWinner(t *testing.T) {
	server, _ := newGraphServer(t)
	token := graphAdmin(t, server)
	graphCall(t, server, token, "POST", "/graph/commands", graphSeed())
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for _, cmd := range []map[string]interface{}{graphMove("left", 1, 1), graphMove("right", 2, 1)} {
		wg.Add(1)
		go func(cmd map[string]interface{}) {
			defer wg.Done()
			status, _ := graphCall(t, server, token, "POST", "/graph/commands", cmd)
			statuses <- status
		}(cmd)
	}
	wg.Wait()
	close(statuses)
	won, conflicted := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusOK:
			won++
		case http.StatusConflict:
			conflicted++
		default:
			t.Fatalf("unexpected status %d", status)
		}
	}
	if won != 1 || conflicted != 1 {
		t.Fatalf("wanted one winner and one conflict, got %d/%d", won, conflicted)
	}
}
