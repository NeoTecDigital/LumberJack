// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

const (
	scopeID  = "1111111111111111111111111111111111111111111111111111111111111111"
	taskID   = "2222222222222222222222222222222222222222222222222222222222222222"
	otherID  = "3333333333333333333333333333333333333333333333333333333333333333"
	occID    = "4444444444444444444444444444444444444444444444444444444444444444"
	edgeID   = "5555555555555555555555555555555555555555555555555555555555555555"
	cycleOcc = "6666666666666666666666666666666666666666666666666666666666666666"
)

var testNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func raw(value interface{}) json.RawMessage { b, _ := json.Marshal(value); return b }

func entity(id, kind string) map[string]interface{} {
	return map[string]interface{}{"id": id, "kind": kind, "title": "T"}
}

func occurrence(id, entityID, scope string, x int64) map[string]interface{} {
	return map[string]interface{}{"id": id, "entity_id": entityID, "scope_id": scope,
		"geometry": map[string]int64{"x": x, "y": 0, "width": 1000, "height": 1000, "scale": 1000000}}
}

func put(collection, id string, value interface{}) Operation {
	return Operation{Op: "put", Collection: collection, ID: id, Value: raw(value)}
}

func move(id string, x int64) Command {
	return Command{ID: id, Fingerprint: id, Actor: "agent:a",
		Expected:   Expected{Occurrences: map[string]uint64{occID: 1}, Topology: map[string]uint64{scopeID: 1}},
		Operations: []Operation{put(CollectionOccurrences, occID, occurrence(occID, taskID, scopeID, x))}}
}

func seedCommand() Command {
	return Command{ID: "seed", Fingerprint: "seed-v1",
		Expected: Expected{Entities: map[string]uint64{scopeID: 0, taskID: 0}, Occurrences: map[string]uint64{occID: 0}, Topology: map[string]uint64{scopeID: 0}},
		Operations: []Operation{
			put(CollectionEntities, scopeID, entity(scopeID, "scope")),
			put(CollectionEntities, taskID, entity(taskID, "task")),
			put(CollectionOccurrences, occID, occurrence(occID, taskID, scopeID, 0)),
		}}
}

func seed(t *testing.T) *core.Node {
	t.Helper()
	forest := core.NewForest("root")
	if _, err := commit(forest, seedCommand(), "admin", testNow); err != nil {
		t.Fatal(err)
	}
	return forest
}

func remove(collection, id string) Operation {
	return Operation{Op: "delete", Collection: collection, ID: id}
}

// commit runs one command through an engine that has kept nothing, so every command in these
// tests is decoded out of the forest and checked whole: what a test reads back is what the forest
// holds. engine_test.go runs the same engine KEPT across commands and holds the two to each other.
func commit(forest *core.Node, cmd Command, userID string, now time.Time) (Result, error) {
	return NewEngine(nil).Commit(forest, cmd, userID, now)
}

func snapshot(t *testing.T, forest *core.Node) Snapshot {
	t.Helper()
	snap, err := NewEngine(nil).Snapshot(forest)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func entityNode(t *testing.T, forest *core.Node, id string) *core.Node {
	t.Helper()
	_, lay, err := load(Root(forest))
	if err != nil {
		t.Fatal(err)
	}
	node := lay.node(CollectionEntities, id)
	if node == nil {
		t.Fatalf("entity %s has no node", id)
	}
	return node
}

func TestSeedLaysOutContainmentAsParentage(t *testing.T) {
	forest := seed(t)
	root := Root(forest)
	if root == nil || root.Name != RootName {
		t.Fatal("graph root missing")
	}
	task, scope := entityNode(t, forest, taskID), entityNode(t, forest, scopeID)
	if _, ok := task.Parents[scope.ID]; !ok || len(task.Parents) != 1 || scope.Children[task.ID] != task {
		t.Fatalf("task is not contained by its scope: parents %v", task.Parents)
	}
	if _, ok := scope.Parents[root.ID]; !ok || root.Children[task.ID] != nil {
		t.Fatal("unscoped entity must hang from the graph root, scoped one must not")
	}
	if task.Kind != "task" || task.Name != taskID {
		t.Fatalf("entity node kind/name = %q/%q", task.Kind, task.Name)
	}
	if root.Children[bucketID(CollectionOccurrences)].Children[nodeID(CollectionOccurrences, occID)] == nil {
		t.Fatal("occurrence is not under _occurrences")
	}
	snap := snapshot(t, forest)
	if snap.Revision != 1 || recordUint(snap.Entities[scopeID], "topology_revision") != 1 || recordUint(snap.Occurrences[occID], "revision") != 1 {
		t.Fatalf("revisions wrong: %+v", snap)
	}
	if _, found, _ := ReceiptFor(forest, "seed"); !found {
		t.Fatal("receipt not stored")
	}
}

func TestRejectsBadCandidateWithoutChange(t *testing.T) {
	forest := seed(t)
	before := raw(snapshot(t, forest))
	entries := len(Root(forest).Entries)
	bad := move("bad", 0)
	bad.Operations[0].Value = raw(map[string]interface{}{"id": occID, "entity_id": taskID, "scope_id": scopeID,
		"geometry": map[string]interface{}{"x": 1.5, "y": 0, "width": 1, "height": 1, "scale": 1}})
	if _, err := commit(forest, bad, "admin", testNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted fractional geometry: %v", err)
	}
	if after := raw(snapshot(t, forest)); string(after) != string(before) {
		t.Fatalf("invalid candidate changed the forest:\n%s\n%s", before, after)
	}
	if len(Root(forest).Entries) != entries {
		t.Fatal("invalid candidate was journaled")
	}
	if _, found, _ := ReceiptFor(forest, "bad"); found {
		t.Fatal("invalid candidate left a receipt")
	}
}

func TestRejectsForgedIdentityAndLostViewUpdate(t *testing.T) {
	forest := seed(t)
	upper := strings.Repeat("A", 32) + strings.Repeat("a", 32)
	forged := Command{ID: "forged", Fingerprint: "forged", Expected: Expected{Entities: map[string]uint64{upper: 0}},
		Operations: []Operation{put(CollectionEntities, upper, entity(upper, "task"))}}
	if _, err := commit(forest, forged, "admin", testNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("upper-case id accepted: %v", err)
	}
	blank := Command{ID: "blank", Fingerprint: "blank", Expected: Expected{Entities: map[string]uint64{otherID: 0}},
		Operations: []Operation{put(CollectionEntities, otherID, entity(otherID, " "))}}
	if _, err := commit(forest, blank, "admin", testNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("blank kind accepted: %v", err)
	}
	first := Command{ID: "view-first", Fingerprint: "view-first", Expected: Expected{Views: map[string]uint64{"monitor": 0}},
		Operations: []Operation{put(CollectionViews, "monitor", map[string]interface{}{"id": "monitor", "name": "Monitor"})}}
	if _, err := commit(forest, first, "admin", testNow); err != nil {
		t.Fatal(err)
	}
	stale := first
	stale.ID, stale.Fingerprint = "view-stale", "view-stale"
	_, err := commit(forest, stale, "admin", testNow)
	var conflict *Conflict
	if !errors.As(err, &conflict) || !errors.Is(err, ErrConflict) {
		t.Fatalf("view lost-update was not rejected: %v", err)
	}
	if conflict.Collection != CollectionViews || conflict.ID != "monitor" || conflict.Expected != 0 || conflict.Actual != 1 || !conflict.Stale {
		t.Fatalf("conflict does not name the disagreement: %+v", conflict)
	}
}

func TestReplayReturnsOriginalAndReuseConflicts(t *testing.T) {
	forest := seed(t)
	cmd := move("move-1", 2500)
	first, err := commit(forest, cmd, "admin", testNow)
	if err != nil || first.Replayed || first.Revision != 2 || first.Changes[0].Revision != 2 {
		t.Fatalf("first = %+v, %v", first, err)
	}
	second, err := commit(forest, cmd, "admin", testNow.Add(time.Hour))
	if err != nil || !second.Replayed || second.Revision != 2 || len(second.Changes) != 1 || second.Changes[0] != first.Changes[0] {
		t.Fatalf("replay = %+v, %v", second, err)
	}
	if snapshot(t, forest).Revision != 2 {
		t.Fatal("replay advanced the revision")
	}
	reused := move("move-1", 9)
	if _, err := commit(forest, reused, "admin", testNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused id with a different payload: %v", err)
	}
	receipt, found, _ := ReceiptFor(forest, "move-1")
	if !found || receipt.Fingerprint != "move-1" || receipt.Actor != "agent:a" {
		t.Fatalf("receipt = %+v", receipt)
	}
}

func TestPutKeepsEngineOwnedTopologyRevision(t *testing.T) {
	forest := seed(t)
	rename := Command{ID: "rename", Fingerprint: "rename", Expected: Expected{Entities: map[string]uint64{scopeID: 1}},
		Operations: []Operation{put(CollectionEntities, scopeID, map[string]interface{}{"id": scopeID, "kind": "scope", "title": "Renamed", "topology_revision": 99})}}
	if _, err := commit(forest, rename, "admin", testNow); err != nil {
		t.Fatal(err)
	}
	scope := snapshot(t, forest).Entities[scopeID]
	if recordUint(scope, "topology_revision") != 1 || recordUint(scope, "revision") != 2 || recordString(scope, "title") != "Renamed" {
		t.Fatalf("put erased or accepted a topology revision: %s", recordText(scope))
	}
	if _, err := commit(forest, move("move-after", 7), "admin", testNow); err != nil {
		t.Fatalf("topology expectation no longer matches after a plain put: %v", err)
	}
}

func TestKindIsImmutable(t *testing.T) {
	forest := seed(t)
	cmd := Command{ID: "rekind", Fingerprint: "rekind", Expected: Expected{Entities: map[string]uint64{taskID: 1}},
		Operations: []Operation{put(CollectionEntities, taskID, entity(taskID, "note"))}}
	if _, err := commit(forest, cmd, "admin", testNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("kind changed: %v", err)
	}
}

func TestContainmentCycleRefused(t *testing.T) {
	forest := seed(t)
	cmd := Command{ID: "cycle", Fingerprint: "cycle",
		Expected:   Expected{Occurrences: map[string]uint64{cycleOcc: 0}, Topology: map[string]uint64{taskID: 0}},
		Operations: []Operation{put(CollectionOccurrences, cycleOcc, occurrence(cycleOcc, scopeID, taskID, 0))}}
	_, err := commit(forest, cmd, "admin", testNow)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "containment cycle") {
		t.Fatalf("cycle accepted: %v", err)
	}
	if len(entityNode(t, forest, scopeID).Parents) != 1 {
		t.Fatal("refused cycle changed parentage")
	}
}

func TestPutAppendsHistoryEntry(t *testing.T) {
	forest := seed(t)
	if _, err := commit(forest, move("move-1", 2500), "alice", testNow); err != nil {
		t.Fatal(err)
	}
	_, lay, _ := load(Root(forest))
	entries := lay.node(CollectionOccurrences, occID).Entries
	if len(entries) != 2 {
		t.Fatalf("history entries = %d", len(entries))
	}
	content := entries[1].Content.(map[string]interface{})
	prior, _ := content["prior"].(string)
	if content["command_id"] != "move-1" || content["actor"] != "agent:a" || entries[1].UserID != "alice" || !strings.Contains(prior, `"x":0`) {
		t.Fatalf("history entry = %+v", entries[1])
	}
	if entries[0].Content.(map[string]interface{})["prior"] != nil {
		t.Fatal("creation history must hold no prior value")
	}
}

func TestOccurrencesMoveAndRemoveParentage(t *testing.T) {
	forest := seed(t)
	rescope := Command{ID: "rescope", Fingerprint: "rescope",
		Expected: Expected{Entities: map[string]uint64{otherID: 0}, Occurrences: map[string]uint64{occID: 1}, Topology: map[string]uint64{scopeID: 1, otherID: 0}},
		Operations: []Operation{
			put(CollectionEntities, otherID, entity(otherID, "scope")),
			put(CollectionOccurrences, occID, occurrence(occID, taskID, otherID, 0)),
		}}
	if _, err := commit(forest, rescope, "admin", testNow); err != nil {
		t.Fatal(err)
	}
	task, other := entityNode(t, forest, taskID), entityNode(t, forest, otherID)
	if _, ok := task.Parents[other.ID]; !ok || len(task.Parents) != 1 || len(entityNode(t, forest, scopeID).Children) != 0 {
		t.Fatalf("task did not move scopes: %v", task.Parents)
	}
	snap := snapshot(t, forest)
	if recordUint(snap.Entities[scopeID], "topology_revision") != 2 || recordUint(snap.Entities[otherID], "topology_revision") != 1 {
		t.Fatal("topology revisions did not follow the membership change")
	}
	remove := Command{ID: "remove", Fingerprint: "remove",
		Expected:   Expected{Entities: map[string]uint64{taskID: 1}, Occurrences: map[string]uint64{occID: 2}, Topology: map[string]uint64{otherID: 1}},
		Operations: []Operation{{Op: "delete", Collection: CollectionOccurrences, ID: occID}, {Op: "delete", Collection: CollectionEntities, ID: taskID}}}
	if _, err := commit(forest, remove, "admin", testNow); err != nil {
		t.Fatal(err)
	}
	snap = snapshot(t, forest)
	if _, ok := snap.Entities[taskID]; ok || len(snap.Occurrences) != 0 || len(entityNode(t, forest, otherID).Children) != 0 {
		t.Fatal("delete left the entity or its link behind")
	}
}

func TestEdgesAliasesAndViewsAreValidated(t *testing.T) {
	forest := seed(t)
	cmd := Command{ID: "extras", Fingerprint: "extras", Expected: Expected{Views: map[string]uint64{"board": 0}, Topology: map[string]uint64{scopeID: 1}},
		Operations: []Operation{
			put(CollectionEdges, edgeID, map[string]interface{}{"id": edgeID, "source": scopeID, "target": taskID, "scope_id": scopeID, "relation": "contains"}),
			put(CollectionAliases, "main-task", taskID),
			put(CollectionViews, "board", map[string]interface{}{"id": "board", "entity_ids": []string{taskID}}),
		}}
	if _, err := commit(forest, cmd, "admin", testNow); err != nil {
		t.Fatal(err)
	}
	snap := snapshot(t, forest)
	if snap.Aliases["main-task"] != taskID || recordUint(snap.Edges[edgeID], "revision") != 1 || recordUint(snap.Views["board"], "revision") != 1 {
		t.Fatalf("extras not stored: %+v", snap)
	}
	dangling := Command{ID: "dangling", Fingerprint: "dangling", Operations: []Operation{put(CollectionAliases, "ghost", otherID)}}
	if _, err := commit(forest, dangling, "admin", testNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("alias to a missing target accepted: %v", err)
	}
	unexpected := Command{ID: "unexpected", Fingerprint: "unexpected",
		Operations: []Operation{put(CollectionEdges, edgeID, map[string]interface{}{"id": edgeID, "source": scopeID, "target": taskID, "scope_id": scopeID, "relation": "r"})}}
	if _, err := commit(forest, unexpected, "admin", testNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("edge change without a topology expectation accepted: %v", err)
	}
}

func TestEventsPageBySinceAndLimit(t *testing.T) {
	forest := seed(t)
	for i, x := range []int64{1, 2} {
		cmd := move("move-"+string(rune('a'+i)), x)
		cmd.Expected.Occurrences[occID] = uint64(i + 1)
		if _, err := commit(forest, cmd, "admin", testNow); err != nil {
			t.Fatal(err)
		}
	}
	first, err := Events(forest, 0, 2)
	if err != nil || len(first.Events) != 2 || first.Next == nil || *first.Next != 2 {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	rest, err := Events(forest, *first.Next, 2)
	if err != nil || len(rest.Events) != 1 || rest.Next != nil || rest.Events[0].Revision != 3 || rest.Events[0].CommandID != "move-b" || rest.Events[0].Actor != "agent:a" {
		t.Fatalf("second page = %+v, %v", rest, err)
	}
	if all, _ := Events(forest, 0, 0); len(all.Events) != 3 || all.Events[0].Changes[0].Op != "put" {
		t.Fatalf("default page = %+v", all)
	}
	if clampLimit(MaxEventLimit+1) != MaxEventLimit {
		t.Fatal("limit not capped")
	}
}
