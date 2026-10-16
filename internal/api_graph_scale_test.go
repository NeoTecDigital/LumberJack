// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/graph"
)

// The scale table: what one single-entity command costs over graphs of growing size, flat and with
// one occurrence per entity. It is opt-in, because seeding twenty thousand entities through a
// durable writer is minutes on a slow disk:
//
//	LUMBERJACK_GRAPH_SCALE=1 go test ./internal -run TestGraphScaleTable -v -timeout 60m
//
// "engine" is the command inside the forest hold and nothing else; "durable" is the whole request,
// which adds serializing the forest and the fsync that acknowledges it.

const (
	graphScaleEnv   = "LUMBERJACK_GRAPH_SCALE"
	graphScaleChunk = 2000
	graphScaleRuns  = 7
)

func graphScaleID(i int) string { return fmt.Sprintf("%064x", 0x100000+i) }

// seedGraphScale commits count entities in chunks, each with one occurrence in a single scope when
// placed is set.
func seedGraphScale(t *testing.T, server *Server, token string, count int, placed bool) {
	t.Helper()
	scope := graphScaleID(count)
	for start, chunk := 0, 0; start < count; start, chunk = start+graphScaleChunk, chunk+1 {
		entities, occurrences := map[string]uint64{}, map[string]uint64{}
		expected := map[string]interface{}{"entities": entities, "occurrences": occurrences}
		operations := []interface{}{}
		if placed && chunk == 0 {
			entities[scope] = 0
			operations = append(operations, graphPut("entities", scope, graphEntity(scope, "scope")))
		}
		for i := start; i < start+graphScaleChunk && i < count; i++ {
			id := graphScaleID(i)
			entities[id] = 0
			operations = append(operations, graphPut("entities", id, map[string]interface{}{"id": id, "kind": "task", "title": fmt.Sprintf("Task %d", i)}))
		}
		for i := start; placed && i < start+graphScaleChunk && i < count; i++ {
			id, occ := graphScaleID(i), graphScaleID(count+1+i)
			occurrences[occ] = 0
			operations = append(operations, graphPut("occurrences", occ, map[string]interface{}{"id": occ, "entity_id": id, "scope_id": scope,
				"geometry": map[string]int64{"x": int64(i), "y": 0, "width": 1000, "height": 1000, "scale": 1000000}}))
		}
		if placed {
			expected["topology"] = map[string]uint64{scope: uint64(chunk)}
		}
		name := fmt.Sprintf("seed-%d", chunk)
		cmd := map[string]interface{}{"id": name, "fingerprint": name, "expected": expected, "operations": operations}
		if status, body := graphCall(t, server, token, "POST", "/graph/commands", cmd); status != http.StatusOK {
			t.Fatalf("seed chunk %d: %d %v", chunk, status, body)
		}
	}
}

func graphScaleRename(run int, revision uint64) map[string]interface{} {
	id, name := graphScaleID(0), fmt.Sprintf("rename-%d", run)
	return map[string]interface{}{"id": name, "fingerprint": name, "expected": map[string]interface{}{"entities": map[string]uint64{id: revision}},
		"operations": []interface{}{graphPut("entities", id, map[string]interface{}{"id": id, "kind": "task", "title": name})}}
}

func median(samples []time.Duration) time.Duration {
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2]
}

// measureGraphScale answers the median engine-only and durable times of one single-entity command.
func measureGraphScale(t *testing.T, server *Server, token string) (time.Duration, time.Duration) {
	t.Helper()
	engine, durable := []time.Duration{}, []time.Duration{}
	revision := uint64(1)
	for run := 0; run < graphScaleRuns; run++ {
		var cmd graph.Command
		encoded, _ := json.Marshal(graphScaleRename(run*2, revision))
		if err := json.Unmarshal(encoded, &cmd); err != nil {
			t.Fatal(err)
		}
		server.forestMutex.Lock()
		started := time.Now()
		_, err := server.graph.Commit(server.forest, cmd, "scale", time.Now().UTC())
		engine = append(engine, time.Since(started))
		server.forestMutex.Unlock()
		if err != nil {
			t.Fatalf("engine commit: %v", err)
		}
		revision++
		started = time.Now()
		if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphScaleRename(run*2+1, revision)); status != http.StatusOK {
			t.Fatalf("durable commit: %d %v", status, body)
		}
		durable = append(durable, time.Since(started))
		revision++
	}
	return median(engine), median(durable)
}

func TestGraphScaleTable(t *testing.T) {
	if os.Getenv(graphScaleEnv) == "" {
		t.Skipf("set %s=1 to measure", graphScaleEnv)
	}
	for _, placed := range []bool{false, true} {
		for _, count := range []int{2000, 10000, 20000} {
			server, _ := newGraphServer(t)
			token := graphAdmin(t, server)
			seedGraphScale(t, server, token, count, placed)
			engine, durable := measureGraphScale(t, server, token)
			shape := "flat"
			if placed {
				shape = "one occurrence each"
			}
			t.Logf("%6d entities, %-19s: engine %-12s durable %s", count, shape, engine, durable)
		}
	}
}
