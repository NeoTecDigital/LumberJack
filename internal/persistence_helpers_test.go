// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// What the persistence, durability and race tests share: a fresh store in directories the test
// chose, in either mode, driven through the main router by the admin a fresh install made.

// storeName names the store's files: the state file is storeName.dat and the hot log beside it is
// storeName.dat.log.<sequence>.
const storeName = "store"

// storeConfig is a fresh snapshot-mode install whose state and logs live in directories the test
// chose.
func storeConfig(dataDir, logDir string) types.ServerConfig {
	return types.ServerConfig{Organization: "test_org", Process: types.ProcessInfo{
		ID: "store_process", Name: storeName, ServerURL: "localhost", ServerPort: "8080", LogPath: logDir, DatabasePath: dataDir}}
}

// tieredConfig is a fresh tiered install whose cold writer never fires on its own, so a test
// decides when the state file is written.
func tieredConfig(t *testing.T, hotSync string) types.ServerConfig {
	t.Helper()
	config := storeConfig(t.TempDir(), t.TempDir())
	config.Persistence = types.PersistenceConfig{Mode: types.PersistenceTiered, HotSync: hotSync,
		HotSyncIntervalMS: 5, ColdEveryCommits: 1 << 30, ColdEverySeconds: 1 << 20}
	config.Sync = types.DefaultSync()
	return config
}

// inEachMode runs check once per persistence mode, each over a fresh install, for a contract that
// must hold in both.
func inEachMode(t *testing.T, check func(t *testing.T, config types.ServerConfig)) {
	t.Helper()
	t.Run(types.PersistenceSnapshot, func(t *testing.T) { check(t, storeConfig(t.TempDir(), t.TempDir())) })
	t.Run(types.PersistenceTiered, func(t *testing.T) { check(t, tieredConfig(t, types.HotSyncCommit)) })
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

// storeAdmin is a session for the admin account a fresh install made.
func storeAdmin(t *testing.T, server *Server) string {
	t.Helper()
	for _, user := range server.forest.Users {
		if user.Username == "admin" {
			return sessionFor(t, server, user.ID, user.Username)
		}
	}
	t.Fatal("no admin account")
	return ""
}

// storeCall sends a request through the MAIN router, session and all, and answers the status and
// the body decoded as a JSON object, when it is one.
func storeCall(t *testing.T, server *Server, token, method, target string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	request := httptest.NewRequest(method, target, bytes.NewReader(encoded))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := serve(t, server, request)
	var decoded map[string]interface{}
	_ = json.Unmarshal(recorder.Body.Bytes(), &decoded)
	return recorder.Code, decoded
}

// workLog is a workspace command that logs one entry on a node. It carries a client id, so a retry
// of the same command is answered from its receipt rather than applied a second time.
func workLog(clientID, path, content string) map[string]interface{} {
	return map[string]interface{}{"command": "log", "path": path, "client_id": clientID, "content": content}
}

// entriesOn is how many entries the node at path holds, or -1 when there is no such node.
func entriesOn(server *Server, path string) int {
	count := -1
	server.readForest(func() {
		if node, err := server.getNodeFromPath(path); err == nil {
			count = len(node.Entries)
		}
	})
	return count
}

// refuseDisk makes every write of the store fail until the returned function is called, by
// making its directory read-only. In snapshot mode that refuses the temporary file every snapshot
// is written through. In tiered mode an open segment is still writable, so the log is first asked
// to start a new segment, which the directory refuses.
func refuseDisk(t *testing.T, server *Server, config types.ServerConfig) func() {
	t.Helper()
	requireUnprivileged(t)
	if server.tier != nil {
		server.tier.log.RollAfter(server.tier.log.LastStaged())
	}
	dir := config.Process.DatabasePath
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(restore)
	return restore
}

// scaleNode is the path of the i-th node seedNodes creates.
func scaleNode(i int) string { return fmt.Sprintf("scale/n%05d", i) }

// seedNodes creates count leaves under scale/ in ONE write, so a test of a large store does not
// pay a write per node to build it.
func seedNodes(t *testing.T, server *Server, count int) {
	t.Helper()
	userID := ""
	for _, user := range server.forest.Users {
		if user.Username == "admin" {
			userID = user.ID
		}
	}
	err := server.changeForest(func() error {
		for i := 0; i < count; i++ {
			if _, err := server.createNodePath(scaleNode(i), core.LeafNode, userID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed %d nodes: %v", count, err)
	}
}

// titleWrite is one ordinary write to a seeded node: its metadata title.
func titleWrite(t *testing.T, server *Server, token string, i int, title string) (int, map[string]interface{}) {
	t.Helper()
	return storeCall(t, server, token, "PATCH", "/nodes/"+scaleNode(i)+"/metadata", map[string]interface{}{"title": title})
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

// logSegments is every hot-log segment beside the store's state file.
func logSegments(t *testing.T, config types.ServerConfig) []string {
	t.Helper()
	return dataDirHas(t, config.Process.DatabasePath, storeName+".dat.log.*")
}
