// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// tieredConfig is a fresh tiered install whose cold writer never fires on its own, so a test
// decides when the state file is written.
func tieredConfig(t *testing.T, hotSync string) types.ServerConfig {
	t.Helper()
	config := graphConfig(t.TempDir(), t.TempDir())
	config.Persistence = types.PersistenceConfig{Mode: types.PersistenceTiered, HotSync: hotSync,
		HotSyncIntervalMS: 5, ColdEveryCommits: 1 << 30, ColdEverySeconds: 1 << 20}
	config.Sync = types.DefaultSync()
	return config
}

func newServerWith(t *testing.T, config types.ServerConfig) *Server {
	t.Helper()
	server, err := NewServer(config, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	return server
}

// abandon drops a server the way a kill would: no snapshot, no sync, no close.
func abandon(server *Server) {
	if tier := server.tier; tier != nil {
		tier.stopCold()
		tier.log.Abandon()
		server.tier = nil
	}
}

// reopenWith comes back over the same files, after a clean shutdown or after a kill.
func reopenWith(t *testing.T, server *Server, config types.ServerConfig, clean bool) *Server {
	t.Helper()
	if clean {
		if err := server.Shutdown(context.Background()); err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	} else {
		abandon(server)
	}
	reopened, err := LoadServer(config)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Shutdown(context.Background()) })
	return reopened
}

var (
	timestampPattern = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`)
	identityPattern  = regexp.MustCompile(`"(id|user_id|created_by|modified_by|uploaded_by|parent_id|entry_id|command_id|actor)":"[^"]*"`)
)

// fingerprint is a forest by what two independent runs of the same operations must agree on:
// names, kinds, structure, metadata, entries and events — not ids minted from the clock, and not
// timestamps.
func fingerprint(forest *core.Node) string {
	lines := []string{}
	walkForest(forest, func(node *core.Node, children []string) {
		names := []string{}
		for _, child := range node.Children {
			names = append(names, child.Name)
		}
		sort.Strings(names)
		users := []string{}
		for _, user := range node.Users {
			users = append(users, user.Username)
		}
		// An empty metadata map is omitted by the codec and comes back nil, in every mode.
		var metadata map[string]interface{}
		if len(node.Metadata) > 0 {
			metadata = node.Metadata
		}
		view := map[string]interface{}{"name": node.Name, "kind": node.Kind, "type": node.Type, "children": names,
			"metadata": metadata, "entries": node.Entries, "events": node.Events, "planned": node.PlannedEvents, "users": users}
		encoded, _ := json.Marshal(view)
		line := timestampPattern.ReplaceAllString(string(encoded), "T")
		lines = append(lines, identityPattern.ReplaceAllString(line, `"$1":"-"`))
	})
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func dataDirHas(t *testing.T, dir, pattern string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func TestTieredCommandsAppendToTheLogAndLeaveTheStateFileAlone(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	token := graphAdmin(t, server)
	before, err := os.Stat(StatePath(config))
	if err != nil {
		t.Fatalf("the install must leave a state file: %v", err)
	}
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphSeed()); status != http.StatusOK {
		t.Fatalf("seed: %d %v", status, body)
	}
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphMove("move-a", 1, 1)); status != http.StatusOK {
		t.Fatalf("move: %d %v", status, body)
	}
	after, _ := os.Stat(StatePath(config))
	if !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Fatal("a command rewrote the state file")
	}
	if segments := dataDirHas(t, config.Process.DatabasePath, "graph.dat.log.*"); len(segments) != 1 {
		t.Fatalf("log segments: %v", segments)
	}
	expected := fingerprint(server.forest)
	reopened := reopenWith(t, server, config, false)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatalf("the forest after a kill is not the forest before it:\n%s\n---\n%s", got, expected)
	}
}

// opScript is a random sequence of graph commands and ordinary writes, replayed identically in
// each mode. Reopen points are part of the script.
type opScript struct {
	ops []func(t *testing.T, server *Server, token string)
}

func randomScript(seed int64, length int) opScript {
	random := rand.New(rand.NewSource(seed))
	revisions := map[string]uint64{}
	script := opScript{}
	for i := 0; i < length; i++ {
		node := fmt.Sprintf("work/n%d", random.Intn(6))
		event := fmt.Sprintf("ev%d", random.Intn(4))
		entity := fmt.Sprintf("%064x", 0x5000+random.Intn(5))
		text := fmt.Sprintf("entry %d", i)
		switch random.Intn(8) {
		case 0, 1:
			script.ops = append(script.ops, func(t *testing.T, s *Server, tok string) {
				graphCall(t, s, tok, "POST", "/nodes", map[string]string{"path": node, "type": "leaf"})
			})
		case 2:
			script.ops = append(script.ops, func(t *testing.T, s *Server, tok string) {
				graphCall(t, s, tok, "POST", "/events/start", map[string]interface{}{"path": node, "event_id": event})
			})
		case 3:
			script.ops = append(script.ops, func(t *testing.T, s *Server, tok string) {
				graphCall(t, s, tok, "POST", "/events/append", map[string]interface{}{"path": node, "event_id": event, "content": text})
			})
		case 4:
			script.ops = append(script.ops, func(t *testing.T, s *Server, tok string) {
				graphCall(t, s, tok, "PATCH", "/nodes/"+node+"/metadata", map[string]interface{}{"label": text})
			})
		case 5:
			script.ops = append(script.ops, func(t *testing.T, s *Server, tok string) {
				graphCall(t, s, tok, "DELETE", "/nodes/"+node+"?mode=cascade", nil)
			})
		default:
			name := fmt.Sprintf("cmd-%d-%d", seed, i)
			script.ops = append(script.ops, func(t *testing.T, s *Server, tok string) {
				revision := revisions[entity]
				cmd := map[string]interface{}{"id": name, "fingerprint": name, "actor": "agent:script",
					"expected":   map[string]interface{}{"entities": map[string]uint64{entity: revision}},
					"operations": []interface{}{graphPut("entities", entity, map[string]interface{}{"id": entity, "kind": "task", "title": text})}}
				if status, _ := graphCall(t, s, tok, "POST", "/graph/commands", cmd); status == http.StatusOK {
					revisions[entity] = revision + 1
				}
			})
		}
	}
	return script
}

// runScript plays a script in one mode, reopening at the given points, and answers the final
// forest's fingerprint. Odd reopen points are kills; even ones are clean shutdowns.
func runScript(t *testing.T, config types.ServerConfig, script opScript, reopenAt map[int]bool) string {
	t.Helper()
	server := newServerWith(t, config)
	token := graphAdmin(t, server)
	for i, op := range script.ops {
		op(t, server, token)
		if reopenAt[i] {
			expected := fingerprint(server.forest)
			server = reopenWith(t, server, config, i%2 == 0)
			token = graphAdmin(t, server)
			if got := fingerprint(server.forest); got != expected {
				t.Fatalf("op %d: the forest did not survive the reopen", i)
			}
		}
	}
	return fingerprint(server.forest)
}

func TestSnapshotAndTieredModesEndInTheSameForest(t *testing.T) {
	for _, seed := range []int64{1, 2, 3} {
		reopenAt := map[int]bool{}
		random := rand.New(rand.NewSource(seed * 7))
		for i := 0; i < 5; i++ {
			reopenAt[random.Intn(60)] = true
		}
		// The script is built once per run: it tracks the revisions its own commands produced.
		snapshot := runScript(t, graphConfig(t.TempDir(), t.TempDir()), randomScript(seed, 60), reopenAt)
		tiered := runScript(t, tieredConfig(t, types.HotSyncCommit), randomScript(seed, 60), reopenAt)
		if snapshot != tiered {
			t.Fatalf("seed %d: the modes disagree\n--- snapshot\n%s\n--- tiered\n%s", seed, snapshot, tiered)
		}
		// The script must have exercised both kinds of write for the agreement to mean anything.
		if !strings.Contains(snapshot, `"name":"graph"`) || !strings.Contains(snapshot, `"events":{"ev`) {
			t.Fatalf("seed %d: the script did not exercise both kinds of write", seed)
		}
	}
}

// seedTiered makes a few commits and answers the forest's fingerprint.
func seedTiered(t *testing.T, server *Server, token string) string {
	t.Helper()
	graphCall(t, server, token, "POST", "/nodes", map[string]string{"path": "work/a", "type": "leaf"})
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphSeed()); status != http.StatusOK {
		t.Fatalf("seed: %d %v", status, body)
	}
	for i := 1; i <= 3; i++ {
		name := fmt.Sprintf("move-%d", i)
		if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphMove(name, int64(i), uint64(i))); status != http.StatusOK {
			t.Fatalf("%s: %d %v", name, status, body)
		}
	}
	return fingerprint(server.forest)
}

func TestAStateFileWrittenButNotYetTrimmedReopensCleanly(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	token := graphAdmin(t, server)
	expected := seedTiered(t, server, token)
	segments := dataDirHas(t, config.Process.DatabasePath, "graph.dat.log.*")
	kept := map[string][]byte{}
	for _, path := range segments {
		data, _ := os.ReadFile(path)
		kept[path] = data
	}
	if _, err := server.snapshotCold(); err != nil {
		t.Fatal(err)
	}
	if left := dataDirHas(t, config.Process.DatabasePath, "graph.dat.log.*"); len(left) != 0 {
		t.Fatalf("segments left after the snapshot: %v", left)
	}
	// The crash: the state file landed, the trim did not.
	for path, data := range kept {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	reopened := reopenWith(t, server, config, false)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatal("the forest differs after reopening over a covered log")
	}
	if left := dataDirHas(t, config.Process.DatabasePath, "graph.dat.log.*"); len(left) == 0 {
		t.Fatal("the reopen deleted the covered segments before writing a state file of its own")
	}
}

func TestARecordAppendedButNotAcknowledgedIsKeptAcrossAKill(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	token := graphAdmin(t, server)
	expected := seedTiered(t, server, token)
	// The record of the last command is in the log; the process dies before answering.
	reopened := reopenWith(t, server, config, false)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatal("an appended record was lost")
	}
	// The caller retries the last command with the same id and is replayed, not reapplied.
	token = graphAdmin(t, reopened)
	status, body := graphCall(t, reopened, token, "POST", "/graph/commands", graphMove("move-3", 3, 3))
	if status != http.StatusOK || body["replayed"] != true {
		t.Fatalf("retry: %d %v", status, body)
	}
}

func TestASnapshotInterruptedMidwayLeavesTheLogAuthoritative(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	token := graphAdmin(t, server)
	expected := seedTiered(t, server, token)
	// The interrupted snapshot: a temporary file half written, never renamed.
	if err := os.WriteFile(StatePath(config)+".tmp", []byte("LUMBERJACK-STATE-2\nhalf"), 0600); err != nil {
		t.Fatal(err)
	}
	reopened := reopenWith(t, server, config, false)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatal("the forest differs after an interrupted snapshot")
	}
	// A clean close now completes the snapshot and the log is trimmed.
	if err := reopened.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if left := dataDirHas(t, config.Process.DatabasePath, "graph.dat.log.*"); len(left) != 0 {
		t.Fatalf("segments left after a clean close: %v", left)
	}
	final, err := LoadServer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Shutdown(context.Background())
	if got := fingerprint(final.forest); got != expected {
		t.Fatal("the forest differs after the completed snapshot")
	}
}

func TestTheChangeSequenceContinuesAfterARestart(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	token := graphAdmin(t, server)
	seedTiered(t, server, token)
	server.mutations.mutex.Lock()
	before := server.mutations.sequence
	server.mutations.mutex.Unlock()
	if before == 0 {
		t.Fatal("nothing was published")
	}
	for _, clean := range []bool{true, false} {
		server = reopenWith(t, server, config, clean)
		token = graphAdmin(t, server)
		graphCall(t, server, token, "POST", "/nodes", map[string]string{"path": fmt.Sprintf("work/after-%v", clean), "type": "leaf"})
		server.mutations.mutex.Lock()
		after := server.mutations.sequence
		server.mutations.mutex.Unlock()
		if after <= before {
			t.Fatalf("clean=%v: the sequence went from %d to %d across the restart", clean, before, after)
		}
		before = after
	}
}

func TestTieredIsRefusedOnAnEncryptedStore(t *testing.T) {
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", key)
	config := tieredConfig(t, types.HotSyncCommit)
	_, err := NewServer(config, core.User{Username: "admin", Password: "admin"})
	if err == nil || !strings.Contains(err.Error(), `persistence.mode "tiered" is not available on an encrypted store`) {
		t.Fatalf("encrypted store: %v", err)
	}
	if segments := dataDirHas(t, config.Process.DatabasePath, "graph.dat.log.*"); len(segments) != 0 {
		t.Fatalf("a log was created on an encrypted store: %v", segments)
	}
}

func TestSyncRolesThisBuildDoesNotRunAreRefusedAtOpen(t *testing.T) {
	for _, mode := range []string{types.PersistenceSnapshot, types.PersistenceTiered} {
		config := tieredConfig(t, types.HotSyncCommit)
		config.Persistence.Mode = mode
		config.Sync = types.SyncConfig{Role: types.SyncRolePrimary, Listen: ":0", Ack: types.SyncAckLocal}
		_, err := NewServer(config, core.User{Username: "admin", Password: "admin"})
		if err == nil || !strings.Contains(err.Error(), `sync.role "primary" is not available in this build`) {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	config := tieredConfig(t, types.HotSyncCommit)
	config.Persistence.HotSync = "later"
	if _, err := NewServer(config, core.User{Username: "admin", Password: "admin"}); err == nil || !strings.Contains(err.Error(), "persistence.hot_sync") {
		t.Fatalf("invalid hot_sync: %v", err)
	}
}

func TestIntervalAndNoneModesRecoverWhatTheyAcknowledged(t *testing.T) {
	for _, hotSync := range []string{types.HotSyncInterval, types.HotSyncNone} {
		t.Run(hotSync, func(t *testing.T) {
			config := tieredConfig(t, hotSync)
			server := newServerWith(t, config)
			token := graphAdmin(t, server)
			expected := seedTiered(t, server, token)
			reopened := reopenWith(t, server, config, true)
			if got := fingerprint(reopened.forest); got != expected {
				t.Fatal("the forest differs after a clean reopen")
			}
		})
	}
}
