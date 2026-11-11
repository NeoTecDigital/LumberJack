// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/types"
)

// The write path tiered persistence shares with snapshot mode and every other mutation: one
// source-fence permit around the whole write, and the staged-scope protection around the change,
// whichever persistence makes it durable.

// Once a fenced write's outcome is unknown, no later write can land in either mode: every one
// takes the same permit, and the fence refuses it before the change is made.
func TestWritesHoldTheSourceFenceInBothModes(t *testing.T) {
	inEachMode(t, writesHoldTheSourceFence)
}

func writesHoldTheSourceFence(t *testing.T, config types.ServerConfig) {
	server := newServerWith(t, config)
	token := storeAdmin(t, server)
	server.sourceFence().requireFencing()
	err := server.changeForest(func() error {
		server.forest.Metadata = map[string]interface{}{"outside": "changed but unacknowledged"}
		return errors.New("synthetic callback failure after live mutation")
	})
	if err == nil || !server.sourceFence().unknown {
		t.Fatal("a failed fenced write did not leave the fence unknown")
	}
	if status, body := storeCall(t, server, token, "POST", "/nodes", map[string]string{"path": "work/past-the-fence", "type": "leaf"}); status == http.StatusOK {
		t.Fatalf("a write landed past an unknown fence: %v", body)
	}
	if _, err := server.getNodeFromPath("work/past-the-fence"); err == nil {
		t.Fatal("a refused write still created its node")
	}
}

// Tiered mode refuses the writers that publish whole paired snapshots through the state writer,
// before they change anything — including the fence, which they would otherwise raise for good.
func TestTieredRefusesWholeStateWriters(t *testing.T) {
	server := newServerWith(t, tieredConfig(t, types.HotSyncCommit))
	requireTieredRefusal(t, "domain", server.ConfigureDomain(DomainConfig{}, nil, nil))
	_, err := server.ConfigurePersonalSource(PersonalSourceConfig{})
	requireTieredRefusal(t, "personal source", err)
	server.forestMutex.Lock()
	_, err = server.encodeSnapshotLocked(server.statePath(), false)
	server.forestMutex.Unlock()
	requireTieredRefusal(t, "whole-state snapshot", err)
	if server.sourceFence().required || server.domain != nil || server.personalSource.Load() != nil {
		t.Fatal("a refused configuration still raised the fence or installed itself")
	}
}

// A state file that already holds an owned scope does not open in tiered mode.
func TestTieredDoesNotOpenAStoreHoldingAnOwnedScope(t *testing.T) {
	directory := t.TempDir()
	owned := stagedTestServer(t, directory)
	if err := owned.configureStagedScope(stagedTestBinding(), stagedTestBounds()); err != nil {
		t.Fatal(err)
	}
	config := types.ServerConfig{Process: types.ProcessInfo{Name: "staged", DatabasePath: directory}}
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
