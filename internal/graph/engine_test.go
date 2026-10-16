// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// agree fails unless a kept engine holds exactly what a fresh decode of the forest holds — the
// collections, the tombstones and the index — and unless that graph passes the whole-graph check
// the kept engine no longer runs on every command.
func agree(t *testing.T, step string, kept *Engine, forest *core.Node) {
	t.Helper()
	fresh, _, err := load(Root(forest))
	if err != nil {
		t.Fatalf("%s: the forest no longer decodes: %v", step, err)
	}
	if err := validateState(fresh); err != nil {
		t.Fatalf("%s: the forest holds a graph the whole check refuses: %v", step, err)
	}
	if have, want := string(raw(kept.state.snapshot())), string(raw(fresh.snapshot())); have != want {
		t.Fatalf("%s: kept state left the forest:\n%s\n%s", step, have, want)
	}
	if !reflect.DeepEqual(kept.state.Tombstones, fresh.Tombstones) {
		t.Fatalf("%s: kept tombstones left the forest:\n%v\n%v", step, kept.state.Tombstones, fresh.Tombstones)
	}
	if !reflect.DeepEqual(kept.state.index, fresh.index) {
		t.Fatalf("%s: kept index is not the index of what the forest holds", step)
	}
}

// picture is everything a kept state holds, as text, for telling whether a refusal changed it.
func picture(state *State) string {
	if state == nil {
		return ""
	}
	return fmt.Sprintf("%s %v %v", raw(state.snapshot()), state.Tombstones, state.index)
}

// keptSteps is a history that reaches every kind of change: creation, geometry, membership moving
// between scopes, edges, aliases, views, deletes, re-creation over a tombstone, and refusals.
func keptSteps() []struct {
	cmd  Command
	fail error
} {
	edge := map[string]interface{}{"id": edgeID, "source": scopeID, "target": taskID, "scope_id": otherID, "relation": "blocks"}
	board := map[string]interface{}{"id": "board", "entity_ids": []string{taskID}, "occurrence_ids": []string{occID}}
	bad := move("bad", 0)
	bad.Expected.Occurrences[occID] = 2
	bad.Operations[0].Value = raw(map[string]interface{}{"id": occID, "entity_id": taskID, "scope_id": scopeID,
		"geometry": map[string]interface{}{"x": 1.5, "y": 0, "width": 1, "height": 1, "scale": 1}})
	return []struct {
		cmd  Command
		fail error
	}{
		{cmd: seedCommand()},
		{cmd: move("move", 2500)},
		{cmd: bad, fail: ErrInvalid},
		{cmd: Command{ID: "rescope", Fingerprint: "f",
			Expected: Expected{Entities: map[string]uint64{otherID: 0}, Occurrences: map[string]uint64{occID: 2}, Topology: map[string]uint64{scopeID: 1, otherID: 0}},
			Operations: []Operation{put(CollectionEntities, otherID, entity(otherID, "scope")),
				put(CollectionOccurrences, occID, occurrence(occID, taskID, otherID, 0))}}},
		{cmd: Command{ID: "extras", Fingerprint: "f", Expected: Expected{Views: map[string]uint64{"board": 0}, Topology: map[string]uint64{otherID: 1}},
			Operations: []Operation{put(CollectionEdges, edgeID, edge), put(CollectionAliases, "main", taskID), put(CollectionViews, "board", board)}}},
		{cmd: Command{ID: "orphan", Fingerprint: "f", Expected: Expected{Entities: map[string]uint64{taskID: 1}},
			Operations: []Operation{remove(CollectionEntities, taskID)}}, fail: ErrInvalid},
		{cmd: Command{ID: "cycle", Fingerprint: "f", Expected: Expected{Occurrences: map[string]uint64{cycleOcc: 0}, Topology: map[string]uint64{taskID: 0}},
			Operations: []Operation{put(CollectionOccurrences, cycleOcc, occurrence(cycleOcc, otherID, taskID, 0))}}, fail: ErrInvalid},
		{cmd: Command{ID: "clear", Fingerprint: "f",
			Expected: Expected{Entities: map[string]uint64{taskID: 1}, Occurrences: map[string]uint64{occID: 3}, Views: map[string]uint64{"board": 1}, Topology: map[string]uint64{otherID: 2}},
			Operations: []Operation{remove(CollectionViews, "board"), remove(CollectionAliases, "main"), remove(CollectionEdges, edgeID),
				remove(CollectionOccurrences, occID), remove(CollectionEntities, taskID)}}},
		{cmd: Command{ID: "reused-zero", Fingerprint: "f", Expected: Expected{Entities: map[string]uint64{taskID: 0}},
			Operations: []Operation{put(CollectionEntities, taskID, entity(taskID, "task"))}}, fail: ErrConflict},
		{cmd: Command{ID: "return", Fingerprint: "f",
			Expected: Expected{Entities: map[string]uint64{taskID: 1}, Occurrences: map[string]uint64{occID: 3}, Topology: map[string]uint64{scopeID: 2}},
			Operations: []Operation{put(CollectionEntities, taskID, entity(taskID, "task")),
				put(CollectionOccurrences, occID, occurrence(occID, taskID, scopeID, 9))}}},
		{cmd: Command{ID: "drop-scope", Fingerprint: "f", Expected: Expected{Entities: map[string]uint64{otherID: 1}},
			Operations: []Operation{remove(CollectionEntities, otherID)}}},
		{cmd: Command{ID: "scope-back", Fingerprint: "f", Expected: Expected{Entities: map[string]uint64{otherID: 1}},
			Operations: []Operation{put(CollectionEntities, otherID, entity(otherID, "scope"))}}},
	}
}

// One engine KEPT across a whole history holds, after every command, what the forest holds — and a
// command it refuses changes neither. This is what stands in for decoding and checking the whole
// graph on every command.
func TestKeptEngineAgreesWithTheForestAfterEveryCommand(t *testing.T) {
	forest, kept := core.NewForest("root"), NewEngine(nil)
	for _, step := range keptSteps() {
		before := picture(kept.state)
		_, err := kept.Commit(forest, step.cmd, "admin", testNow)
		if step.fail == nil && err != nil {
			t.Fatalf("%s: %v", step.cmd.ID, err)
		}
		if step.fail != nil && (!errors.Is(err, step.fail) || picture(kept.state) != before) {
			t.Fatalf("%s: want %v with the kept state untouched, got %v", step.cmd.ID, step.fail, err)
		}
		agree(t, step.cmd.ID, kept, forest)
	}
	snap := snapshot(t, forest)
	if recordUint(snap.Entities[taskID], "revision") != 2 || recordUint(snap.Occurrences[occID], "revision") != 4 {
		t.Fatalf("re-created records did not continue their revisions: %s", raw(snap))
	}
	if recordUint(snap.Entities[otherID], "revision") != 2 || recordUint(snap.Entities[otherID], "topology_revision") != 3 {
		t.Fatalf("a re-created scope lost its counters: %s", recordText(snap.Entities[otherID]))
	}
	if entityNode(t, forest, taskID).Parents[entityNode(t, forest, scopeID).ID] == "" {
		t.Fatal("a re-created entity was not linked under its scope")
	}
}

// A kept engine decodes again when the graph it kept is not the one in the forest any more.
func TestKeptEngineDecodesAgainWhenTheForestMovedWithoutIt(t *testing.T) {
	forest, kept := core.NewForest("root"), NewEngine(nil)
	if _, err := kept.Commit(forest, seedCommand(), "admin", testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := commit(forest, move("elsewhere", 7), "admin", testNow); err != nil {
		t.Fatal(err)
	}
	stale := move("stale", 8)
	if _, err := kept.Commit(forest, stale, "admin", testNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("a kept engine answered from a graph the forest had left: %v", err)
	}
	agree(t, "after another writer", kept, forest)
	replaced := core.NewForest("root")
	if snap, err := kept.Snapshot(replaced); err != nil || snap.Revision != 0 || len(snap.Entities) != 0 {
		t.Fatalf("a kept engine answered for a forest it was not decoded from: %+v, %v", snap, err)
	}
}

// A delete is refused while anything still names the record, whichever kind of record names it and
// by whichever field. The engine no longer checks every record on every command, so each of these
// is found through the index alone.
func TestDeleteIsRefusedWhileAnythingStillNamesTheRecord(t *testing.T) {
	edge := func(source, target, scope string) Operation {
		return put(CollectionEdges, edgeID, map[string]interface{}{"id": edgeID, "source": source, "target": target, "scope_id": scope, "relation": "r"})
	}
	view := func(field, id string) Operation {
		return put(CollectionViews, "v", map[string]interface{}{"id": "v", field: []string{id}})
	}
	dropOther := Command{ID: "drop", Fingerprint: "drop", Expected: Expected{Entities: map[string]uint64{otherID: 1}},
		Operations: []Operation{remove(CollectionEntities, otherID)}}
	dropOcc := Command{ID: "drop", Fingerprint: "drop", Expected: Expected{Occurrences: map[string]uint64{occID: 1}, Topology: map[string]uint64{scopeID: 1}},
		Operations: []Operation{remove(CollectionOccurrences, occID)}}
	cases := []struct {
		name     string
		names    Operation
		topology map[string]uint64
		drop     Command
	}{
		{"nothing", Operation{}, nil, dropOther},
		{"occurrence entity_id", put(CollectionOccurrences, cycleOcc, occurrence(cycleOcc, otherID, scopeID, 0)), map[string]uint64{scopeID: 1}, dropOther},
		{"occurrence scope_id", put(CollectionOccurrences, cycleOcc, occurrence(cycleOcc, taskID, otherID, 0)), map[string]uint64{otherID: 0}, dropOther},
		{"edge source", edge(otherID, taskID, scopeID), map[string]uint64{scopeID: 1}, dropOther},
		{"edge target", edge(taskID, otherID, scopeID), map[string]uint64{scopeID: 1}, dropOther},
		{"edge scope_id", edge(taskID, scopeID, otherID), map[string]uint64{otherID: 0}, dropOther},
		{"view entity_ids", view("entity_ids", otherID), nil, dropOther},
		{"alias to an entity", put(CollectionAliases, "a", otherID), nil, dropOther},
		{"view occurrence_ids", view("occurrence_ids", occID), nil, dropOcc},
		{"alias to an occurrence", put(CollectionAliases, "a", occID), nil, dropOcc},
	}
	for _, c := range cases {
		forest, kept := core.NewForest("root"), NewEngine(nil)
		setup := []Command{seedCommand(), {ID: "other", Fingerprint: "other", Expected: Expected{Entities: map[string]uint64{otherID: 0}},
			Operations: []Operation{put(CollectionEntities, otherID, entity(otherID, "task"))}}}
		if c.names.Op != "" {
			setup = append(setup, Command{ID: "names", Fingerprint: "names", Operations: []Operation{c.names},
				Expected: Expected{Occurrences: map[string]uint64{cycleOcc: 0}, Views: map[string]uint64{"v": 0}, Topology: c.topology}})
		}
		for _, cmd := range setup {
			if _, err := kept.Commit(forest, cmd, "admin", testNow); err != nil {
				t.Fatalf("%s: setup %s: %v", c.name, cmd.ID, err)
			}
		}
		_, err := kept.Commit(forest, c.drop, "admin", testNow)
		if named := c.names.Op != ""; named != errors.Is(err, ErrInvalid) || (!named && err != nil) {
			t.Fatalf("%s: deleting the record it names answered %v", c.name, err)
		}
		agree(t, c.name, kept, forest)
	}
}

// A snapshot is encoded after the forest has been let go, while the next command runs. The kept
// state hands out the records it holds, so this is safe only because no record is ever written in
// place — which the race detector holds it to.
func TestSnapshotsAreEncodedWhileCommandsRun(t *testing.T) {
	forest, engine := core.NewForest("root"), NewEngine(nil)
	other := Command{ID: "other", Fingerprint: "other", Expected: Expected{Entities: map[string]uint64{otherID: 0}},
		Operations: []Operation{put(CollectionEntities, otherID, entity(otherID, "scope"))}}
	for _, cmd := range []Command{seedCommand(), other} {
		if _, err := engine.Commit(forest, cmd, "admin", testNow); err != nil {
			t.Fatal(err)
		}
	}
	var hold sync.RWMutex // stands in for the forest's one lock
	var readers sync.WaitGroup
	done := make(chan struct{})
	for reader := 0; reader < 4; reader++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				hold.RLock()
				snap, err := engine.Snapshot(forest)
				hold.RUnlock()
				if encoded := raw(snap); err != nil || len(snap.Entities) != 3 || len(encoded) == 0 {
					t.Errorf("snapshot under load: %v, %d entities", err, len(snap.Entities))
					return
				}
			}
		}()
	}
	topology := map[string]uint64{scopeID: 1, otherID: 0}
	for i, from, to := 0, scopeID, otherID; i < 200; i, from, to = i+1, to, from {
		name := fmt.Sprintf("hop-%d", i)
		cmd := Command{ID: name, Fingerprint: name,
			Expected:   Expected{Occurrences: map[string]uint64{occID: uint64(i + 1)}, Topology: map[string]uint64{from: topology[from], to: topology[to]}},
			Operations: []Operation{put(CollectionOccurrences, occID, occurrence(occID, taskID, to, int64(i)))}}
		hold.Lock()
		_, err := engine.Commit(forest, cmd, "admin", testNow)
		hold.Unlock()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		topology[from], topology[to] = topology[from]+1, topology[to]+1
	}
	close(done)
	readers.Wait()
	agree(t, "after the run", engine, forest)
}

// Item 2. A delete keeps the node, its history and a tombstone; the id then continues from the
// tombstone's revision and keeps its kind, so neither "it does not exist" nor a stale revision
// writes over what replaced the record.
func TestDeleteLeavesATombstoneAndRecreationContinuesFromIt(t *testing.T) {
	forest := seed(t)
	live := entityNode(t, forest, taskID)
	gone := Command{ID: "gone", Fingerprint: "gone", Actor: "agent:d",
		Expected:   Expected{Entities: map[string]uint64{taskID: 1}, Occurrences: map[string]uint64{occID: 1}, Topology: map[string]uint64{scopeID: 1}},
		Operations: []Operation{remove(CollectionOccurrences, occID), remove(CollectionEntities, taskID)}}
	if _, err := commit(forest, gone, "admin", testNow); err != nil {
		t.Fatal(err)
	}
	if snap := snapshot(t, forest); len(snap.Entities) != 1 || len(snap.Occurrences) != 0 || strings.Contains(string(raw(snap)), "prior") {
		t.Fatalf("a tombstone is in the reported collections: %s", raw(snap))
	}
	state, lay, _ := load(Root(forest))
	k := key{CollectionEntities, taskID}
	tomb, node := state.Tombstones[k], lay.tombs[k]
	if tomb.Revision != 1 || tomb.Kind != "task" || !strings.Contains(string(tomb.Prior), `"title":"T"`) {
		t.Fatalf("tombstone = %+v", tomb)
	}
	if node != live || len(node.Entries) != 2 || Root(forest).Children[bucketID(tombstonesCollection)].Children[node.ID] != node || len(node.Parents) != 1 {
		t.Fatalf("the deleted entity's node was not kept under _tombstones with its history: %d entries, parents %v", len(node.Entries), node.Parents)
	}
	last := node.Entries[1].Content.(map[string]interface{})
	if prior, _ := last["prior"].(string); last["type"] != kindDelete || last["command_id"] != "gone" || last["actor"] != "agent:d" || !strings.Contains(prior, `"kind":"task"`) {
		t.Fatalf("delete history entry = %+v", last)
	}
	if lay.tombs[key{CollectionOccurrences, occID}] == nil || len(entityNode(t, forest, scopeID).Children) != 0 {
		t.Fatal("the deleted occurrence left no tombstone, or left its entity linked")
	}

	back := func(id string, expected uint64, kind string) (Result, error) {
		return commit(forest, Command{ID: id, Fingerprint: id, Expected: Expected{Entities: map[string]uint64{taskID: expected}},
			Operations: []Operation{put(CollectionEntities, taskID, entity(taskID, kind))}}, "admin", testNow)
	}
	var conflict *Conflict
	if _, err := back("as-new", 0, "task"); !errors.As(err, &conflict) || !conflict.Stale || conflict.Actual != 1 {
		t.Fatalf("a deleted id was re-created as if it had never existed: %v", err)
	}
	if _, err := back("rekind", 1, "note"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a deleted id came back as another kind: %v", err)
	}
	result, err := back("back", 1, "task")
	if err != nil || result.Changes[0].Revision != 2 {
		t.Fatalf("re-creation = %+v, %v", result, err)
	}
	again := entityNode(t, forest, taskID)
	if again != live || len(again.Entries) != 3 || again.Metadata[tombstoneKey] != nil || again.Parents[Root(forest).ID] == "" {
		t.Fatalf("re-creation did not take the same node up again: %d entries, parents %v", len(again.Entries), again.Parents)
	}
	if _, err := back("stale", 1, "task"); !errors.As(err, &conflict) || conflict.Actual != 2 {
		t.Fatalf("a writer that last saw revision 1 wrote over the re-created record: %v", err)
	}
	place := Command{ID: "place", Fingerprint: "place", Expected: Expected{Occurrences: map[string]uint64{occID: 1}, Topology: map[string]uint64{scopeID: 2}},
		Operations: []Operation{put(CollectionOccurrences, occID, occurrence(occID, taskID, scopeID, 3))}}
	if result, err := commit(forest, place, "admin", testNow); err != nil || result.Changes[0].Revision != 2 {
		t.Fatalf("occurrence re-creation = %+v, %v", result, err)
	}
}

// Item 3. A value that states an id states the operation's.
func TestValueIDThatDiffersFromTheOperationIDIsRefused(t *testing.T) {
	forest := seed(t)
	before := string(raw(snapshot(t, forest)))
	for name, value := range map[string]interface{}{
		"another": entity(taskID, "task"),
		"number":  map[string]interface{}{"id": 7, "kind": "task"},
	} {
		cmd := Command{ID: name, Fingerprint: name, Expected: Expected{Entities: map[string]uint64{otherID: 0}},
			Operations: []Operation{put(CollectionEntities, otherID, value)}}
		_, err := commit(forest, cmd, "admin", testNow)
		stated := string(raw(value.(map[string]interface{})["id"]))
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), stated) || !strings.Contains(err.Error(), otherID) {
			t.Fatalf("%s: a value.id of %s under operation id %s was not refused naming both: %v", name, stated, otherID, err)
		}
	}
	if after := string(raw(snapshot(t, forest))); after != before {
		t.Fatal("a refused value.id changed the graph")
	}
	absent := Command{ID: "absent", Fingerprint: "absent", Expected: Expected{Entities: map[string]uint64{otherID: 0}},
		Operations: []Operation{put(CollectionEntities, otherID, map[string]interface{}{"kind": "task"})}}
	if _, err := commit(forest, absent, "admin", testNow); err != nil || recordString(snapshot(t, forest).Entities[otherID], "id") != otherID {
		t.Fatalf("a value without an id must take the operation's: %v", err)
	}
}

// Item 4. While the forest is ahead of its file a new command is refused and changes nothing; the
// command that was applied is still replayed, which is how its caller converges.
func TestNewCommandsAreRefusedWhileBehindAndReplaysAreNot(t *testing.T) {
	behind := false
	forest, engine := core.NewForest("root"), NewEngine(func() bool { return behind })
	first, err := engine.Commit(forest, seedCommand(), "admin", testNow)
	if err != nil {
		t.Fatal(err)
	}
	behind = true
	before := picture(engine.state)
	if _, err := engine.Commit(forest, move("new", 5), "admin", testNow); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a new command was taken while the forest was ahead of its file: %v", err)
	}
	if picture(engine.state) != before || len(Root(forest).Entries) != 1 {
		t.Fatal("a refused command changed the graph")
	}
	if _, found, _ := ReceiptFor(forest, "new"); found {
		t.Fatal("a refused command left a receipt")
	}
	retry, err := engine.Commit(forest, seedCommand(), "admin", testNow)
	if err != nil || !retry.Replayed || retry.Revision != first.Revision {
		t.Fatalf("the retry of an applied command was not replayed: %+v, %v", retry, err)
	}
	behind = false
	if result, err := engine.Commit(forest, move("new", 5), "admin", testNow); err != nil || result.Replayed || result.Revision != 2 {
		t.Fatalf("the command was not taken once a flush had succeeded: %+v, %v", result, err)
	}
}

// Item 5. The digest is of the actor the BODY supplied, so a retry that leaves it out again
// replays whichever session sends it, and one that changes what it supplies is another command.
func TestReplayDigestCoversTheActorAsSupplied(t *testing.T) {
	forest := seed(t)
	unnamed := move("unnamed", 5)
	unnamed.Actor = ""
	if _, err := commit(forest, unnamed, "alice", testNow); err != nil {
		t.Fatal(err)
	}
	supplied := unnamed
	if _, err := prepare(&supplied); err != nil {
		t.Fatal(err)
	}
	receipt, _, _ := ReceiptFor(forest, "unnamed")
	if receipt.Actor != "alice" || receipt.PayloadDigest != commandDigest(supplied) {
		t.Fatalf("receipt = %+v", receipt)
	}
	if result, err := commit(forest, unnamed, "bob", testNow); err != nil || !result.Replayed {
		t.Fatalf("a retry under another session's default actor did not replay: %+v, %v", result, err)
	}
	named := unnamed
	named.Actor = "alice"
	if _, err := commit(forest, named, "alice", testNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("a retry that supplied a different actor replayed: %v", err)
	}
}

// Item 6. Nothing the engine answers or stores carries a field the contract does not name.
func TestCommandResultAndReceiptCarryOnlyContractFields(t *testing.T) {
	forest := seed(t)
	receipt, _, _ := ReceiptFor(forest, "seed")
	stored := metaText(Root(forest).Children[bucketID(commandsCollection)].Children[nodeID(commandsCollection, "seed")].Metadata, recordKey)
	for _, text := range []string{string(raw(seedCommand())), string(raw(receipt)), string(raw(receipt.Result)), stored} {
		if strings.Contains(text, "client_fingerprint") || strings.Contains(text, "result_metadata") {
			t.Fatalf("an out-of-contract field is still carried: %s", text)
		}
	}
	if keys := reflect.TypeOf(Result{}).NumField(); keys != 4 {
		t.Fatalf("Result has %d fields, the contract names command_id, revision, changes and replayed", keys)
	}
}
