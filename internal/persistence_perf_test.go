// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// The persistence table: one graph command, durable, over stores of growing size and history, in
// snapshot mode and in tiered mode with each hot_sync. Opt-in, and run on a real disk:
//
//	LUMBERJACK_PERSIST_PERF=1 LUMBERJACK_PERSIST_PERF_DIR=/home/you/perf go test ./internal -run TestPersistencePerformanceTable -v -timeout 60m
//
// The directory defaults to ~/.cache/lumberjack-perf, which is under /home rather than tmpfs.
const (
	persistPerfEnv    = "LUMBERJACK_PERSIST_PERF"
	persistPerfDirEnv = "LUMBERJACK_PERSIST_PERF_DIR"
	persistPerfRuns   = 7
)

func perfDir(t *testing.T) string {
	t.Helper()
	base := os.Getenv(persistPerfDirEnv)
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".cache", "lumberjack-perf")
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "store-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func perfConfig(t *testing.T, mode, hotSync string) types.ServerConfig {
	t.Helper()
	config := graphConfig(perfDir(t), t.TempDir())
	config.Persistence = types.PersistenceConfig{Mode: mode, HotSync: hotSync, HotSyncIntervalMS: 20, ColdEveryCommits: 1 << 30, ColdEverySeconds: 1 << 20}
	config.Sync = types.DefaultSync()
	return config
}

func perfServer(t *testing.T, config types.ServerConfig) *Server {
	t.Helper()
	server, err := NewServer(config, core.User{Username: "admin", Password: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	return server
}

// measureDurable is the median of persistPerfRuns single-entity commands through the whole
// request, starting from revision.
func measureDurable(t *testing.T, server *Server, token string, revision uint64) (time.Duration, uint64) {
	t.Helper()
	samples := []time.Duration{}
	for run := 0; run < persistPerfRuns; run++ {
		cmd := graphScaleRename(int(revision)+1000, revision)
		started := time.Now()
		if status, body := graphCall(t, server, token, "POST", "/graph/commands", cmd); status != http.StatusOK {
			t.Fatalf("durable commit: %d %v", status, body)
		}
		samples = append(samples, time.Since(started))
		revision++
	}
	return median(samples), revision
}

type perfRow struct {
	entities int
	history  int
}

func (row perfRow) String() string {
	if row.history > 0 {
		return fmt.Sprintf("%d entities after %d writes", row.entities, row.history)
	}
	return fmt.Sprintf("%d entities", row.entities)
}

func perfMode(mode, hotSync string) string {
	if mode == types.PersistenceSnapshot {
		return "snapshot"
	}
	return "tiered/" + hotSync
}

func TestPersistencePerformanceTable(t *testing.T) {
	if os.Getenv(persistPerfEnv) == "" {
		t.Skipf("set %s=1 to measure", persistPerfEnv)
	}
	rows := []perfRow{{2000, 0}, {10000, 0}, {20000, 0}, {2000, 5000}}
	modes := [][2]string{{types.PersistenceSnapshot, types.HotSyncCommit}, {types.PersistenceTiered, types.HotSyncCommit}, {types.PersistenceTiered, types.HotSyncInterval}}
	results := map[string]map[string]time.Duration{}
	for _, row := range rows {
		results[row.String()] = map[string]time.Duration{}
		for _, mode := range modes {
			config := perfConfig(t, mode[0], mode[1])
			server := perfServer(t, config)
			token := graphAdmin(t, server)
			seedGraphScale(t, server, token, row.entities, false)
			revision := uint64(1)
			for i := 0; i < row.history; i++ {
				if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphScaleRename(i, revision)); status != http.StatusOK {
					t.Fatalf("history %d: %d %v", i, status, body)
				}
				revision++
			}
			took, _ := measureDurable(t, server, token, revision)
			results[row.String()][perfMode(mode[0], mode[1])] = took
			t.Logf("%-32s %-18s %s", row, perfMode(mode[0], mode[1]), took)
			_ = server.Shutdown(context.Background())
		}
	}
	t.Logf("%-32s %12s %12s %12s", "store", "snapshot", "tiered/commit", "tiered/interval")
	for _, row := range rows {
		r := results[row.String()]
		t.Logf("%-32s %12s %12s %12s", row, r["snapshot"], r["tiered/commit"], r["tiered/interval"])
	}
}

// TestPersistenceWorstCommitDuringSnapshot is the worst single commit latency while the cold
// writer snapshots a ten-thousand-entity store, which is what the hold over the encode costs.
func TestPersistenceWorstCommitDuringSnapshot(t *testing.T) {
	if os.Getenv(persistPerfEnv) == "" {
		t.Skipf("set %s=1 to measure", persistPerfEnv)
	}
	config := perfConfig(t, types.PersistenceTiered, types.HotSyncCommit)
	server := perfServer(t, config)
	token := graphAdmin(t, server)
	seedGraphScale(t, server, token, 10000, false)

	var group sync.WaitGroup
	var worst, quiet atomic.Int64
	var count atomic.Int64
	stop := make(chan struct{})
	snapshotting := atomic.Bool{}
	group.Add(1)
	go func() {
		defer group.Done()
		revision := uint64(1)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			started := time.Now()
			if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphScaleRename(i, revision)); status != http.StatusOK {
				t.Errorf("commit: %d %v", status, body)
				return
			}
			took := int64(time.Since(started))
			revision++
			count.Add(1)
			target := &quiet
			if snapshotting.Load() {
				target = &worst
			}
			if took > target.Load() {
				target.Store(took)
			}
		}
	}()
	time.Sleep(500 * time.Millisecond)
	snapshots := 0
	for i := 0; i < 5; i++ {
		snapshotting.Store(true)
		started := time.Now()
		if _, err := server.snapshotCold(); err != nil {
			t.Fatal(err)
		}
		snapshotting.Store(false)
		snapshots++
		t.Logf("snapshot %d took %s", i, time.Since(started))
		time.Sleep(300 * time.Millisecond)
	}
	close(stop)
	group.Wait()
	t.Logf("%d commits; worst commit outside a snapshot %s; worst commit during a snapshot %s",
		count.Load(), time.Duration(quiet.Load()), time.Duration(worst.Load()))
}
