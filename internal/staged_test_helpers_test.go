// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

func stagedTestBounds() stagedBounds {
	return stagedBounds{MaxNodes: 50, MaxChanges: 20, MaxReceipts: 30,
		MaxIdentifierBytes: 200, MaxValueDepth: 20, MaxScopeBytes: 100000, MaxSnapshotBytes: 1000000}
}

func stagedTestBinding() stagedBinding {
	return stagedBinding{ScopeID: "owned-scope", AccountID: "account-a",
		AccountRootID: "account-root", RootID: "data-root"}
}

func stagedTestServer(t *testing.T, directory string) *Server {
	t.Helper()
	server := &Server{logger: types.NewLogger(), cache: &Cache{},
		config: types.ServerConfig{Process: types.ProcessInfo{Name: "staged", DatabasePath: directory}}}
	server.stateWriter = newStateWriter(server.publishSnapshot)
	server.forest = &core.Node{ID: "forest-id", Name: "forest", Children: map[string]*core.Node{}}
	account := &core.Node{ID: "account-root", Name: "account", Parents: map[string]string{"forest-id": "forest"}, Children: map[string]*core.Node{}}
	data := &core.Node{ID: "data-root", Name: "data", Parents: map[string]string{"account-root": "account"}, Children: map[string]*core.Node{}}
	record := &core.Node{ID: "record-a", Name: "record", Kind: "synthetic-record",
		Parents: map[string]string{"data-root": "data"}, Metadata: map[string]interface{}{"label": "original", "unknown": stagedTestUnknown()}}
	data.Children[record.ID], account.Children[data.ID] = record, data
	server.forest.Children[account.ID] = account
	return server
}

func stagedTestUnknown() map[string]interface{} {
	return map[string]interface{}{"large": json.Number("9007199254740993"), "decimal": json.Number("1.2300e+4"),
		"null": nil, "bool": true, "array": []interface{}{" exact ", nil, json.Number("0.000000001")},
		"object": map[string]interface{}{"unknown-key": "unmodified"}}
}

func stagedTestConfigured(t *testing.T) *Server {
	t.Helper()
	server := stagedTestServer(t, t.TempDir())
	if err := server.configureStagedScope(stagedTestBinding(), stagedTestBounds()); err != nil {
		t.Fatal(err)
	}
	return server
}

func stagedTestAllow(access stagedAccess) error { return nil }

func stagedTestCommand(t *testing.T, server *Server, id string) stagedCommand {
	t.Helper()
	view, err := server.readOwnedScope("owned-scope", stagedTestAllow)
	if err != nil {
		t.Fatal(err)
	}
	return stagedCommand{PrincipalID: "external-human", AccountID: "account-a", ScopeID: "owned-scope",
		CommandID: id, ExpectedRevision: view.Revision, Action: "synthetic.label.set", BodySHA256: stagedHash([]byte(id))}
}

func stagedTestLabel(value string) stagedBuilder {
	return func(view stagedView) (stagedDelta, error) {
		return stagedDelta{Writes: []stagedWrite{{NodeID: "record-a", Key: "label", Value: value}}}, nil
	}
}

func stagedTestDisk(t *testing.T, server *Server) *core.Node {
	t.Helper()
	data, err := os.ReadFile(server.statePath())
	if err != nil {
		t.Fatal(err)
	}
	return forestFromStateBytes(t, data)
}

func stagedTestRecord(t *testing.T, forest *core.Node) *core.Node {
	t.Helper()
	node, err := forest.GetNode("record-a")
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func stagedTestRequireLabel(t *testing.T, node *core.Node, expected string) {
	t.Helper()
	if node.Metadata["label"] != expected {
		t.Fatalf("label = %#v, want %q", node.Metadata["label"], expected)
	}
}

func stagedTestAwait(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("synthetic operation did not reach its boundary")
	}
}

func stagedTestWaitPending(t *testing.T, writer *stateWriter) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		writer.mutex.Lock()
		pending := writer.pending != nil
		writer.mutex.Unlock()
		if pending {
			return
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatal("composed legacy snapshot was not staged")
		}
	}
}
