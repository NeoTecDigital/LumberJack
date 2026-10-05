// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"net/http"
	"os"
	"testing"

	"github.com/NeoTecDigital/LumberJack/types"
)

// A command whose write failed is in memory and not on the disk. A retry of the SAME id finds its
// receipt, and the engine would answer the stored result — but the answer must wait for the
// write, in both modes: a 200 with replayed:true is a promise that the command is durable, and a
// kill before the next successful write would otherwise lose a command the caller was told it
// could forget.
//
// The disk is refused by making the store directory read-only. In snapshot mode that refuses the
// temporary file every snapshot is written through. In tiered mode an open segment is still
// writable, so the log is asked to start a new segment, which the directory refuses.
func TestAReplayIsNotAcknowledgedUntilTheCommandIsDurable(t *testing.T) {
	requireUnprivileged(t)
	for _, mode := range []string{types.PersistenceSnapshot, types.PersistenceTiered} {
		t.Run(mode, func(t *testing.T) {
			config := tieredConfig(t, types.HotSyncCommit)
			config.Persistence.Mode = mode
			server := newServerWith(t, config)
			token := graphAdmin(t, server)
			if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphSeed()); status != http.StatusOK {
				t.Fatalf("seed: %d %v", status, body)
			}

			dir := config.Process.DatabasePath
			if server.tier != nil {
				server.tier.log.RollAfter(server.tier.log.LastStaged())
			}
			if err := os.Chmod(dir, 0500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

			move := graphMove("move-while-down", 7, 1)
			if status, body := graphCall(t, server, token, "POST", "/graph/commands", move); status < 500 {
				t.Fatalf("the write landed on a read-only directory: %d %v", status, body)
			}
			if !server.persistBehind() {
				t.Fatal("the forest is not reported ahead of its store")
			}
			status, body := graphCall(t, server, token, "POST", "/graph/commands", move)
			if status < 500 || body["replayed"] == true {
				t.Fatalf("a replay was acknowledged while the command was not durable: %d %v", status, body)
			}

			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			status, body = graphCall(t, server, token, "POST", "/graph/commands", move)
			if status != http.StatusOK || body["replayed"] != true {
				t.Fatalf("retry after the disk returned: %d %v", status, body)
			}
			if server.persistBehind() {
				t.Fatal("the store is still reported behind after the replay was acknowledged")
			}

			expected := fingerprint(server.forest)
			reopened := reopenWith(t, server, config, false)
			if got := fingerprint(reopened.forest); got != expected {
				t.Fatal("the reopened forest does not hold the replayed command")
			}
			token = graphAdmin(t, reopened)
			if status, body := graphCall(t, reopened, token, "POST", "/graph/commands", move); status != http.StatusOK || body["replayed"] != true {
				t.Fatalf("replay after reopen: %d %v", status, body)
			}
		})
	}
}
