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
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/internal/persist"
	"github.com/NeoTecDigital/LumberJack/types"
)

// requireOK fails the test unless a request was answered 200.
func requireOK(t *testing.T, what string, status int, body map[string]interface{}) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("%s: %d %v", what, status, body)
	}
}

func TestTieredWritesAppendToTheLogAndLeaveTheStateFileAlone(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	token := storeAdmin(t, server)
	before, err := os.Stat(StatePath(config))
	if err != nil {
		t.Fatalf("the install must leave a state file: %v", err)
	}
	status, body := storeCall(t, server, token, "POST", "/nodes", map[string]string{"path": "work/a", "type": "leaf"})
	requireOK(t, "create", status, body)
	status, body = storeCall(t, server, token, "POST", "/events/start", map[string]interface{}{"path": "work/a", "event_id": "ev"})
	requireOK(t, "start", status, body)
	status, body = storeCall(t, server, token, "PATCH", "/nodes/work/a/metadata", map[string]interface{}{"label": "tiered"})
	requireOK(t, "metadata", status, body)
	status, body = storeCall(t, server, token, "POST", "/workspace/commands", workLog("log-a", "work/a", "logged"))
	requireOK(t, "workspace log", status, body)
	after, _ := os.Stat(StatePath(config))
	if !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Fatal("a write rewrote the state file")
	}
	if segments := logSegments(t, config); len(segments) != 1 {
		t.Fatalf("log segments: %v", segments)
	}
	expected := fingerprint(server.forest)
	reopened := reopenWith(t, server, config, false)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatalf("the forest after a kill is not the forest before it:\n%s\n---\n%s", got, expected)
	}
}

// opScript is a random sequence of ordinary writes, replayed identically in each mode. Reopen
// points are part of the script.
type opScript struct {
	ops []func(t *testing.T, server *Server, token string)
}

// scriptRequest is one random write: method, target and body.
func scriptRequest(random *rand.Rand, seed int64, i int) (string, string, interface{}) {
	node := fmt.Sprintf("work/n%d", random.Intn(6))
	event := fmt.Sprintf("ev%d", random.Intn(4))
	text := fmt.Sprintf("entry %d", i)
	switch random.Intn(8) {
	case 0, 1:
		return "POST", "/nodes", map[string]string{"path": node, "type": "leaf"}
	case 2:
		return "POST", "/events/start", map[string]interface{}{"path": node, "event_id": event}
	case 3:
		return "POST", "/events/append", map[string]interface{}{"path": node, "event_id": event, "content": text}
	case 4:
		return "PATCH", "/nodes/" + node + "/metadata", map[string]interface{}{"label": text}
	case 5:
		return "DELETE", "/nodes/" + node + "?mode=cascade", nil
	}
	return "POST", "/workspace/commands", workLog(fmt.Sprintf("log-%d-%d", seed, i), node, text)
}

func randomScript(seed int64, length int) opScript {
	random := rand.New(rand.NewSource(seed))
	script := opScript{}
	for i := 0; i < length; i++ {
		method, target, body := scriptRequest(random, seed, i)
		script.ops = append(script.ops, func(t *testing.T, s *Server, tok string) {
			storeCall(t, s, tok, method, target, body)
		})
	}
	return script
}

// runScript plays a script in one mode, reopening at the given points, and answers the final
// forest's fingerprint. Odd reopen points are kills; even ones are clean shutdowns.
func runScript(t *testing.T, config types.ServerConfig, script opScript, reopenAt map[int]bool) string {
	t.Helper()
	server := newServerWith(t, config)
	token := storeAdmin(t, server)
	for i, op := range script.ops {
		op(t, server, token)
		if reopenAt[i] {
			server = reopenUnchanged(t, server, config, i)
			token = storeAdmin(t, server)
		}
	}
	return fingerprint(server.forest)
}

// reopenUnchanged reopens at script step i — a clean shutdown at an even step, a kill at an odd
// one — and fails unless the reopened forest is the one before it.
func reopenUnchanged(t *testing.T, server *Server, config types.ServerConfig, i int) *Server {
	t.Helper()
	expected := fingerprint(server.forest)
	reopened := reopenWith(t, server, config, i%2 == 0)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatalf("op %d: the forest did not survive the reopen", i)
	}
	return reopened
}

func TestSnapshotAndTieredModesEndInTheSameForest(t *testing.T) {
	for _, seed := range []int64{1, 2, 3} {
		reopenAt := map[int]bool{}
		random := rand.New(rand.NewSource(seed * 7))
		for i := 0; i < 5; i++ {
			reopenAt[random.Intn(60)] = true
		}
		snapshot := runScript(t, storeConfig(t.TempDir(), t.TempDir()), randomScript(seed, 60), reopenAt)
		tiered := runScript(t, tieredConfig(t, types.HotSyncCommit), randomScript(seed, 60), reopenAt)
		if snapshot != tiered {
			t.Fatalf("seed %d: the modes disagree\n--- snapshot\n%s\n--- tiered\n%s", seed, snapshot, tiered)
		}
		// The script must have exercised the event routes and the workspace commands for the
		// agreement to mean anything.
		if !strings.Contains(snapshot, `"category":"log"`) || !strings.Contains(snapshot, `"events":{"ev`) {
			t.Fatalf("seed %d: the script did not exercise both kinds of write", seed)
		}
	}
}

// seedStore makes a few writes, the last of them a workspace command a caller may retry, and
// answers the forest's fingerprint.
func seedStore(t *testing.T, server *Server, token string) string {
	t.Helper()
	status, body := storeCall(t, server, token, "POST", "/nodes", map[string]string{"path": "work/a", "type": "leaf"})
	requireOK(t, "create", status, body)
	status, body = storeCall(t, server, token, "PATCH", "/nodes/work/a/metadata", map[string]interface{}{"label": "seeded"})
	requireOK(t, "metadata", status, body)
	for i := 1; i <= 3; i++ {
		name := fmt.Sprintf("log-%d", i)
		status, body := storeCall(t, server, token, "POST", "/workspace/commands", workLog(name, "work/a", name))
		requireOK(t, name, status, body)
	}
	return fingerprint(server.forest)
}

func TestAStateFileWrittenButNotYetTrimmedReopensCleanly(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	expected := seedStore(t, server, storeAdmin(t, server))
	kept := map[string][]byte{}
	for _, path := range logSegments(t, config) {
		data, _ := os.ReadFile(path)
		kept[path] = data
	}
	if _, err := server.snapshotCold(); err != nil {
		t.Fatal(err)
	}
	if left := logSegments(t, config); len(left) != 0 {
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
	if left := logSegments(t, config); len(left) == 0 {
		t.Fatal("the reopen deleted the covered segments before writing a state file of its own")
	}
}

func TestARecordAppendedButNotAcknowledgedIsKeptAcrossAKill(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	expected := seedStore(t, server, storeAdmin(t, server))
	// The record of the last command is in the log; the process dies before answering.
	reopened := reopenWith(t, server, config, false)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatal("an appended record was lost")
	}
	// The caller retries the last command with the same id and is answered from its receipt, not
	// applied a second time.
	status, body := storeCall(t, reopened, storeAdmin(t, reopened), "POST", "/workspace/commands", workLog("log-3", "work/a", "log-3"))
	if status != http.StatusOK || entriesOn(reopened, "work/a") != 3 {
		t.Fatalf("retry: %d %v, %d entries", status, body, entriesOn(reopened, "work/a"))
	}
}

func TestASnapshotInterruptedMidwayLeavesTheLogAuthoritative(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	expected := seedStore(t, server, storeAdmin(t, server))
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
	if left := logSegments(t, config); len(left) != 0 {
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

// A log written by a build that logged PARTIAL nodes — the entries past an index, or the stored
// children kept — is refused at open, naming what it refused, instead of being applied as whole
// nodes, which would drop the entries and children the record left out.
func TestALogHoldingAPartialNodeIsRefusedAtOpen(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	seedStore(t, server, storeAdmin(t, server))
	node, err := server.getNodeFromPath("work/a")
	if err != nil {
		t.Fatal(err)
	}
	partial, _ := json.Marshal(logNode{Node: node, Children: []string{}, EntriesBefore: len(node.Entries)})
	record, _ := json.Marshal(changeSet{Root: server.forest.ID, Nodes: map[string]json.RawMessage{node.ID: partial}})
	covered := server.tier.lastCold.Load()
	abandon(server)

	hook, err := persist.OpenHook(config.Sync)
	if err != nil {
		t.Fatal(err)
	}
	log, _, err := persist.Open(StatePath(config), config.Persistence, hook, covered)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Commit(log.Stage(record)); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := LoadServer(config)
	if err == nil {
		_ = reopened.Shutdown(context.Background())
		t.Fatal("a log holding a partial node was opened")
	}
	if !strings.Contains(err.Error(), "partial node") {
		t.Fatalf("the refusal does not say what it refused: %v", err)
	}
}

// The stream is numbered from the log's last record on open. Every write here publishes ONE
// mutation per record, which is what that continuation rests on: a write that publishes more than
// one per record — a workspace command publishes two — can leave the restarted numbering below
// what a client saw, and the stream's epoch is what tells that client the process restarted.
func TestTheChangeSequenceContinuesAfterARestart(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	token := storeAdmin(t, server)
	for i := 0; i < 3; i++ {
		path := fmt.Sprintf("work/n%d", i)
		status, body := storeCall(t, server, token, "POST", "/nodes", map[string]string{"path": path, "type": "leaf"})
		requireOK(t, "create", status, body)
		status, body = storeCall(t, server, token, "PATCH", "/nodes/"+path+"/metadata", map[string]interface{}{"label": path})
		requireOK(t, "metadata", status, body)
	}
	server.mutations.mutex.Lock()
	before := server.mutations.sequence
	server.mutations.mutex.Unlock()
	if before == 0 {
		t.Fatal("nothing was published")
	}
	for _, clean := range []bool{true, false} {
		server = reopenWith(t, server, config, clean)
		token := storeAdmin(t, server)
		storeCall(t, server, token, "POST", "/nodes", map[string]string{"path": fmt.Sprintf("work/after-%v", clean), "type": "leaf"})
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
	if segments := logSegments(t, config); len(segments) != 0 {
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
		t.Run(hotSync, func(t *testing.T) { recoversWhatItAcknowledged(t, tieredConfig(t, hotSync)) })
	}
}

func recoversWhatItAcknowledged(t *testing.T, config types.ServerConfig) {
	server := newServerWith(t, config)
	expected := seedStore(t, server, storeAdmin(t, server))
	reopened := reopenWith(t, server, config, true)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatal("the forest differs after a clean reopen")
	}
}
