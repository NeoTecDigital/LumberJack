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
	token := storeAdmin(t, server)
	seedNodes(t, server, 400)

	const writers = 4
	var group sync.WaitGroup
	tally := &commitTally{}
	stop := make(chan struct{})
	for w := 0; w < writers; w++ {
		group.Add(1)
		go func(w int) {
			defer group.Done()
			commitUntil(t, server, token, w, stop, tally)
		}(w)
	}
	snapshots := snapshotFor(t, server, 2*time.Second)
	close(stop)
	group.Wait()
	t.Logf("%d commits across %d snapshots; worst commit %s", tally.commits.Load(), snapshots, time.Duration(tally.worst.Load()))
	if tally.commits.Load() == 0 || snapshots == 0 {
		t.Fatal("nothing ran")
	}

	expected := fingerprint(server.forest)
	reopened := reopenWith(t, server, config, false)
	if got := fingerprint(reopened.forest); got != expected {
		t.Fatal("a commit made during a snapshot was lost")
	}
}

// commitTally counts the commits the writers landed and the slowest of them.
type commitTally struct {
	commits atomic.Int64
	worst   atomic.Int64
}

// commitUntil is one writer: it retitles its own hundred nodes, one durable write at a time,
// until stop closes or a write is refused.
func commitUntil(t *testing.T, server *Server, token string, w int, stop <-chan struct{}, tally *commitTally) {
	for i := 0; ; i++ {
		select {
		case <-stop:
			return
		default:
		}
		name := fmt.Sprintf("w%d-%d", w, i)
		started := time.Now()
		if status, body := titleWrite(t, server, token, w*100+i%100, name); status != http.StatusOK {
			t.Errorf("%s: %d %v", name, status, body)
			return
		}
		tally.commits.Add(1)
		if took := int64(time.Since(started)); took > tally.worst.Load() {
			tally.worst.Store(took)
		}
	}
}

// snapshotFor takes cold snapshots back to back for a while and answers how many it took.
func snapshotFor(t *testing.T, server *Server, length time.Duration) int {
	snapshots := 0
	for deadline := time.Now().Add(length); time.Now().Before(deadline); {
		if _, err := server.snapshotCold(); err != nil {
			t.Errorf("snapshot: %v", err)
		}
		snapshots++
		time.Sleep(20 * time.Millisecond)
	}
	return snapshots
}
