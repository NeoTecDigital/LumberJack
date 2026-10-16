// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/types"
)

// Commits keep landing while the cold writer takes a snapshot, and every one of them is in the
// forest a reopen recovers. Run under -race: the snapshot encodes the forest under the hold and
// writes it with the hold released, while commits stage under the same hold.
func TestCommitsLandDuringAColdSnapshot(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	token := graphAdmin(t, server)
	seedGraphScale(t, server, token, 400, false)

	const writers = 4
	var group sync.WaitGroup
	var commits atomic.Int64
	var worst atomic.Int64
	stop := make(chan struct{})
	for w := 0; w < writers; w++ {
		group.Add(1)
		go func(w int) {
			defer group.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				id := graphScaleID(w*100 + i%100)
				name := fmt.Sprintf("w%d-%d", w, i)
				cmd := map[string]interface{}{"id": name, "fingerprint": name,
					"expected":   map[string]interface{}{"entities": map[string]uint64{id: uint64(i/100 + 1)}},
					"operations": []interface{}{graphPut("entities", id, map[string]interface{}{"id": id, "kind": "task", "title": name})}}
				started := time.Now()
				status, body := graphCall(t, server, token, "POST", "/graph/commands", cmd)
				if status != http.StatusOK {
					t.Errorf("%s: %d %v", name, status, body)
					return
				}
				commits.Add(1)
				if took := int64(time.Since(started)); took > worst.Load() {
					worst.Store(took)
				}
			}
		}(w)
	}
	snapshots := 0
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		if _, err := server.snapshotCold(); err != nil {
			t.Errorf("snapshot: %v", err)
		}
		snapshots++
		time.Sleep(20 * time.Millisecond)
	}
	close(stop)
	group.Wait()
	t.Logf("%d commits across %d snapshots; worst commit %s", commits.Load(), snapshots, time.Duration(worst.Load()))
	if commits.Load() == 0 || snapshots == 0 {
		t.Fatal("nothing ran")
	}

	expected := fingerprint(server.forest)
	reopened := reopenWith(t, server, config, false)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatal("a commit made during a snapshot was lost")
	}
}
