// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
)

func TestStagedReopenIgnoresUnrelatedSnapshotSize(t *testing.T) {
	server, small := mixedScopeFixture(t, 16<<20, 17<<20)
	path := server.statePath()
	reopened := stagedTestServer(t, server.config.Process.DatabasePath)
	if err := reopened.loadFromFile(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sequence := reopened.stateSeq
	if err := reopened.configureStagedScope(stagedTestBinding(), small); err != nil {
		t.Fatal("unrelated populated scope prevented existing scope reopen", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || reopened.stateSeq != sequence {
		t.Fatal("reconfiguring reconciled state rewrote the complete forest", err)
	}
	if _, err := reopened.readOwnedScope("owned-scope", stagedTestAllow); err != nil {
		t.Fatal("reopened scope is not readable", err)
	}
	if _, err := reopened.stageOwnedCommand(stagedTestCommand(t, reopened, "still-bounded"), stagedTestAllow, stagedTestLabel("no")); err == nil {
		t.Fatal("reopen bypassed the existing snapshot bound on NEW writes")
	}
}

func mixedScopeFixture(t *testing.T, maximum, payload int) (*Server, stagedBounds) {
	t.Helper()
	server := stagedTestServer(t, t.TempDir())
	small := stagedTestBounds()
	small.MaxSnapshotBytes = maximum
	if err := server.configureStagedScope(stagedTestBinding(), small); err != nil {
		t.Fatal(err)
	}
	large := addUnrelatedScope(server, payload)
	largeBounds := small
	largeBounds.MaxScopeBytes, largeBounds.MaxSnapshotBytes = payload*2, payload*4
	if err := server.configureStagedScope(large, largeBounds); err != nil {
		t.Fatal(err)
	}
	return server, small
}

func addUnrelatedScope(server *Server, payload int) stagedBinding {
	account := &core.Node{ID: "account-b", Name: "other-account", Parents: map[string]string{server.forest.ID: server.forest.Name}, Children: map[string]*core.Node{}}
	root := &core.Node{ID: "root-b", Name: "other-data", Parents: map[string]string{account.ID: account.Name}, Metadata: map[string]interface{}{"blob": strings.Repeat("b", payload)}}
	account.Children[root.ID], server.forest.Children[account.ID] = root, account
	return stagedBinding{ScopeID: "other-scope", AccountID: "other-account", AccountRootID: account.ID, RootID: root.ID}
}

func TestStagedReopenDoesNotReplaceBoundsOrIgnoreUnknownOutcome(t *testing.T) {
	server, bounds := mixedScopeFixture(t, 4000, 8000)
	changed := bounds
	changed.MaxSnapshotBytes++
	if server.configureStagedScope(stagedTestBinding(), changed) == nil {
		t.Fatal("bounds changed without migration")
	}
	scope := server.stagedScopes["owned-scope"]
	scope.reconciled = false
	if server.configureStagedScope(stagedTestBinding(), bounds) == nil {
		t.Fatal("unreconciled scope bypassed publication evidence")
	}
}

func TestStagedReopenDoesNotIgnoreOwnScopeOrOwnershipLimits(t *testing.T) {
	for _, mode := range []string{"scope-bytes", "foreign-edge", "pending"} {
		t.Run(mode, func(t *testing.T) { refusedReopen(t, mode) })
	}
}

func refusedReopen(t *testing.T, mode string) {
	t.Helper()
	server, bounds := mixedScopeFixture(t, 4000, 8000)
	scope := server.stagedScopes["owned-scope"]
	switch mode {
	case "scope-bytes":
		stagedTestRecord(t, server.forest).Metadata["blob"] = strings.Repeat("x", bounds.MaxScopeBytes+1)
	case "foreign-edge":
		server.forest.Children["alias"] = stagedTestRecord(t, server.forest)
	case "pending":
		scope.pending = &stagedPending{key: "unknown"}
	}
	if server.configureStagedScope(stagedTestBinding(), bounds) == nil {
		t.Fatal("reopen discarded an existing scope protection", mode)
	}
}
