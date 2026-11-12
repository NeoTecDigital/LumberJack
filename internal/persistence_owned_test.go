// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/internal/compat"
	"github.com/NeoTecDigital/LumberJack/types"
)

// Tiered persistence and the stores it must not take: a whole-state snapshot is never handed to the
// state writer under it, and a store holding a legacy owned scope — whose owners run under snapshot
// persistence only — does not open under it.

func TestTieredRefusesWholeStateWriters(t *testing.T) {
	server := newServerWith(t, tieredConfig(t, types.HotSyncCommit))
	server.forestMutex.Lock()
	_, err := server.encodeStateLocked(server.statePath())
	server.forestMutex.Unlock()
	requireTieredRefusal(t, "whole-state snapshot", err)
}

// A state file that already holds an owned scope does not open in tiered mode.
func TestTieredDoesNotOpenAStoreHoldingAnOwnedScope(t *testing.T) {
	directory := t.TempDir()
	owned := compatBareServer(t, directory)
	scope := &core.Node{ID: "owned-root", Name: "owned", Parents: map[string]string{owned.forest.ID: owned.forest.Name},
		CommandReceipts: map[string]interface{}{compat.OwnedScopeMarker: map[string]interface{}{"bounds": map[string]interface{}{"maxNodes": 10}}}}
	owned.forest.Children[scope.ID] = scope
	if err := owned.persistState(owned.statePath()); err != nil {
		t.Fatal(err)
	}
	config := types.ServerConfig{Process: types.ProcessInfo{Name: "compat", DatabasePath: directory}}
	config.Persistence = types.PersistenceConfig{Mode: types.PersistenceTiered, HotSync: types.HotSyncCommit,
		HotSyncIntervalMS: 5, ColdEveryCommits: 1 << 30, ColdEverySeconds: 1 << 20}
	config.Sync = types.DefaultSync()
	server, err := NewCore(config)
	if err == nil {
		_ = server.Shutdown(t.Context())
		t.Fatal("a store holding an owned scope opened in tiered mode")
	}
	requireTieredRefusal(t, "owned scope at open", err)
}

func requireTieredRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), `persistence.mode "tiered"`) {
		t.Fatalf("%s under tiered persistence answered %v, want the tiered refusal", what, err)
	}
}
