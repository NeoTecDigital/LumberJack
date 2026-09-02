package internal

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// THE DEFECT: the state file was fsynced INSIDE the exclusive forest hold, so every request queued
// behind a disk flush. Measured at nineteen seconds under host load 26, and twice more at host load
// ~8.5, which is an ordinary working load. The relay in front of the engine gave up at five seconds
// and reported the datastore UNREACHABLE, while /health — which takes no lock — answered 200 in
// 25ms.
//
// These tests hold the disk busy under real handlers. Against the pre-fix arrangement
// TestForestIsNotHeldWhileTheStateFileIsFlushed fails with a read that waited the whole flush.

// flushDelay is long enough that a hold across it is unmistakable and short enough to keep the
// suite quick. It stands in for the fsync of a congested disk.
const flushDelay = 400 * time.Millisecond

// slowFlushes makes every state file write take at least delay, and reports when the first one is
// in flight. It answers the writes it observed, in the order they were performed.
//
// The seam is the writer's own publish function, so everything above it — handlers, the forest
// lock, the coalescing — is the production path.
func slowFlushes(server *Server, delay time.Duration) (started <-chan struct{}, observed func() []uint64) {
	publish := server.stateWriter.write
	inFlight := make(chan struct{})
	var once sync.Once

	var mutex sync.Mutex
	var order []uint64

	server.stateWriter.write = func(snapshot stateSnapshot) error {
		once.Do(func() { close(inFlight) })
		time.Sleep(delay)
		err := publish(snapshot)
		mutex.Lock()
		order = append(order, snapshot.seq)
		mutex.Unlock()
		return err
	}

	return inFlight, func() []uint64 {
		mutex.Lock()
		defer mutex.Unlock()
		return append([]uint64(nil), order...)
	}
}

// forestFromStateBytes decodes a copy of the state file taken at some instant, without going near
// the live server — a test that asks what is ON THE DISK must not read through the thing it is
// asking about.
func forestFromStateBytes(t *testing.T, raw []byte) *core.Node {
	t.Helper()

	header := len(stateMagic) + sha256.Size
	if len(raw) <= header || string(raw[:len(stateMagic)]) != stateMagic {
		t.Fatalf("The captured state file is not a node table: %d bytes", len(raw))
	}

	reader, err := gzip.NewReader(bytes.NewReader(raw[header:]))
	if err != nil {
		t.Fatalf("Failed to open the captured state file: %v", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("Failed to read the captured state file: %v", err)
	}

	forest, err := decodeState(data)
	if err != nil {
		t.Fatalf("Failed to decode the captured state file: %v", err)
	}
	return forest
}

// A flush in flight does not hold the forest.
//
// This is the stall itself. A read takes the forest for reading and a write takes it exclusively;
// with the fsync inside the exclusive hold, BOTH wait the whole flush, which is how a 19s disk
// became a 5s relay timeout on `user login` and `patch node metadata` alike.
func TestForestIsNotHeldWhileTheStateFileIsFlushed(t *testing.T) {
	dir := t.TempDir()
	server := newServerInDirs(t, dir, dir)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/flush")

	inFlight, _ := slowFlushes(server, flushDelay)

	acknowledged := make(chan int, 1)
	go func() {
		acknowledged <- post(t, server.handleStartEvent, userID, map[string]interface{}{
			"path": path, "event_id": "under-the-flush",
		}).Code
	}()
	<-inFlight

	// A read over the real route and the exclusive hold a write has to take, BOTH measured while
	// the same flush is still in flight — one after the other would let the first absorb the whole
	// flush and leave the second looking free.
	var measuring sync.WaitGroup
	var readWaited, writeWaited time.Duration
	var code int

	measuring.Add(2)
	go func() {
		defer measuring.Done()
		started := time.Now()
		code = get(t, server.handleGetForest, userID, "/forest").Code
		readWaited = time.Since(started)
	}()
	go func() {
		defer measuring.Done()
		started := time.Now()
		server.forestMutex.Lock()
		writeWaited = time.Since(started)
		server.forestMutex.Unlock()
	}()
	measuring.Wait()

	if code != http.StatusOK {
		t.Fatalf("GET /forest during a flush: got %d, want %d", code, http.StatusOK)
	}

	t.Logf("during a %v flush: read waited %v, exclusive hold waited %v", flushDelay, readWaited, writeWaited)

	// A quarter of the flush is a wide margin either way: unheld these are microseconds, held they
	// are the whole flush.
	limit := flushDelay / 4
	if readWaited > limit {
		t.Errorf("A read waited %v behind a %v flush: the forest is held across the disk", readWaited, flushDelay)
	}
	if writeWaited > limit {
		t.Errorf("The exclusive hold waited %v behind a %v flush: the forest is held across the disk", writeWaited, flushDelay)
	}

	if got := <-acknowledged; got != http.StatusOK {
		t.Fatalf("Start event under a slow flush: got %d, want %d", got, http.StatusOK)
	}
}

// A 200 still means the change is on the DISK, even when another request's flush is what put it
// there.
//
// Coalescing is the part that could quietly turn an acknowledgment back into a lie: a caller
// satisfied by somebody else's write is only honest if that write was NEWER than its own change.
// Each cycle reads the file back the moment its 200 arrives.
func TestAnAcknowledgedChangeIsOnDiskBeforeTheAnswer(t *testing.T) {
	dir := t.TempDir()
	server := newServerInDirs(t, dir, dir)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/acknowledged")

	slowFlushes(server, 25*time.Millisecond)

	const cycles = 24
	captured := make([][]byte, cycles)
	codes := make([]int, cycles)

	var waiting sync.WaitGroup
	for cycle := 0; cycle < cycles; cycle++ {
		waiting.Add(1)
		go func(cycle int) {
			defer waiting.Done()

			codes[cycle] = post(t, server.handleStartEvent, userID, map[string]interface{}{
				"path": path, "event_id": fmt.Sprintf("acked-%d", cycle),
			}).Code
			if codes[cycle] != http.StatusOK {
				return
			}
			// The file AS IT IS at the instant of the acknowledgment. os.ReadFile opens the
			// published inode, and the publish is a rename, so this is never a torn file.
			raw, err := os.ReadFile(server.statePath())
			if err == nil {
				captured[cycle] = raw
			}
		}(cycle)
	}
	waiting.Wait()

	for cycle := 0; cycle < cycles; cycle++ {
		if codes[cycle] != http.StatusOK {
			t.Fatalf("Start event %d: got %d, want %d", cycle, codes[cycle], http.StatusOK)
		}
		if captured[cycle] == nil {
			t.Fatalf("Failed to read the state file back after cycle %d was acknowledged", cycle)
		}

		eventID := fmt.Sprintf("acked-%d", cycle)
		node, found := walkNames(forestFromStateBytes(t, captured[cycle]), []string{"work", "acknowledged"})
		if !found {
			t.Fatalf("%s was acknowledged and the node was not in the state file", eventID)
		}
		if _, exists := node.Events[eventID]; !exists {
			t.Fatalf("%s was acknowledged with 200 and was not yet in the state file", eventID)
		}
	}
}

// Concurrent writes land on the disk in the order the forest passed through them, and the last
// state acknowledged is the state the file is left in.
//
// A snapshot is the WHOLE forest, so an out-of-order write is not a redundant write — it is a
// rollback that drops every change made since. Nothing above the writer prevents it: the encodes
// are ordered by the exclusive hold, but the flushes behind them are not.
func TestConcurrentPersistsNeverRollTheStateFileBack(t *testing.T) {
	dir := t.TempDir()
	server := newServerInDirs(t, dir, dir)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/ordered")

	_, observed := slowFlushes(server, 15*time.Millisecond)

	const cycles = 40
	acknowledged := make([]bool, cycles)

	var waiting sync.WaitGroup
	for cycle := 0; cycle < cycles; cycle++ {
		waiting.Add(1)
		go func(cycle int) {
			defer waiting.Done()
			acknowledged[cycle] = post(t, server.handleStartEvent, userID, map[string]interface{}{
				"path": path, "event_id": fmt.Sprintf("ordered-%d", cycle),
			}).Code == http.StatusOK
		}(cycle)
	}
	waiting.Wait()

	order := observed()
	if len(order) < 2 {
		t.Fatalf("Only %d flushes happened: the fixture is not exercising concurrent persists", len(order))
	}
	for i := 1; i < len(order); i++ {
		if order[i] <= order[i-1] {
			t.Fatalf("The state file was written in the order %v: snapshot %d landed after %d", order, order[i], order[i-1])
		}
	}
	t.Logf("%d acknowledged writes cost %d flushes: %v", cycles, len(order), order)

	// The file is the state the last acknowledgment promised: everything that got a 200 is in it.
	persisted := reloadServer(t, dir)
	node, err := persisted.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to read the node back after a restart: %v", err)
	}
	for cycle := 0; cycle < cycles; cycle++ {
		if !acknowledged[cycle] {
			t.Fatalf("Start event %d was refused", cycle)
		}
		if _, exists := node.Events[fmt.Sprintf("ordered-%d", cycle)]; !exists {
			t.Fatalf("ordered-%d was acknowledged with 200 and is not in the state file", cycle)
		}
	}

	// And the file matches memory exactly, not merely a superset of what was asked for.
	live, err := encodeState(server.forest)
	if err != nil {
		t.Fatalf("Failed to serialize the live forest: %v", err)
	}
	fromDisk, err := encodeState(persisted.forest)
	if err != nil {
		t.Fatalf("Failed to serialize the forest that was loaded back: %v", err)
	}
	if !bytes.Equal(live, fromDisk) {
		t.Fatalf("The state file is not the forest that was acknowledged: %d bytes on disk against %d in memory", len(fromDisk), len(live))
	}
}

// A flush that FAILED is not remembered as bytes on disk.
//
// The unchanged-content skip is decided against the hash of the last file successfully written. If
// a failed attempt updated that hash, the next persist of the same forest would be skipped and the
// caller told 200 for a change that never reached the disk.
func TestPersistDoesNotSkipAfterAFailedFlush(t *testing.T) {
	dir := t.TempDir()
	server := newServerInDirs(t, dir, dir)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/failed-flush")

	publish := server.stateWriter.write
	var attempts int
	var mutex sync.Mutex
	server.stateWriter.write = func(snapshot stateSnapshot) error {
		mutex.Lock()
		attempts++
		fail := attempts == 1
		mutex.Unlock()
		if fail {
			return fmt.Errorf("induced disk failure")
		}
		return publish(snapshot)
	}

	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": path, "event_id": "lost-to-the-disk",
	}).Code; code != http.StatusInternalServerError {
		t.Fatalf("A failed flush answered %d, want %d", code, http.StatusInternalServerError)
	}

	// The SAME forest, persisted again: the previous attempt did not put it on the disk, so this
	// one may not be skipped.
	if err := server.persistState(server.statePath()); err != nil {
		t.Fatalf("Persist after a failed flush: %v", err)
	}

	raw, err := os.ReadFile(server.statePath())
	if err != nil {
		t.Fatalf("Failed to read the state file: %v", err)
	}
	node, found := walkNames(forestFromStateBytes(t, raw), []string{"work", "failed-flush"})
	if !found {
		t.Fatalf("The retried persist did not write the node")
	}
	if _, exists := node.Events["lost-to-the-disk"]; !exists {
		t.Fatalf("The persist after a failed flush was skipped: the change is still not on the disk")
	}
}

// Staging keeps the NEWEST snapshot, whatever order snapshots reach the writer in.
//
// Sequence order is decided under the exclusive forest hold; arrival at the writer is not, because
// two goroutines that leave that hold in order are scheduled in whatever order they are scheduled.
// A writer that simply kept whatever arrived last would hold an older whole-forest state.
func TestStateWriterStagesTheNewestSnapshot(t *testing.T) {
	writer := newStateWriter(func(stateSnapshot) error { return nil })

	writer.mutex.Lock()
	writer.stage(stateSnapshot{seq: 3, hash: []byte{3}, path: "state"})
	writer.stage(stateSnapshot{seq: 1, hash: []byte{1}, path: "state"})
	staged := writer.pending.seq
	writer.mutex.Unlock()

	if staged != 3 {
		t.Fatalf("Snapshot %d is staged after 3 arrived: an older whole-forest state is queued to overwrite a newer one", staged)
	}
}

// An older snapshot is never published after a newer one, driven through commit with the
// interleaving that would do it.
//
// A snapshot is the WHOLE forest, so an out-of-order write is not a redundant write — it is a
// rollback that drops every change made since. Nothing above the writer prevents it: the encodes
// are ordered by the exclusive hold, the flushes behind them are not.
func TestStateWriterNeverPublishesAnOlderSnapshotAfterANewer(t *testing.T) {
	var mutex sync.Mutex
	var order []uint64

	release := make(chan struct{})
	flushing := make(chan struct{})
	var once sync.Once

	writer := newStateWriter(func(snapshot stateSnapshot) error {
		mutex.Lock()
		order = append(order, snapshot.seq)
		mutex.Unlock()
		once.Do(func() { close(flushing); <-release })
		return nil
	})

	// Snapshot 2 is on the disk and stays there while the rest of the interleaving is set up.
	first := make(chan struct{})
	go func() {
		defer close(first)
		if err := writer.commit(stateSnapshot{seq: 2, hash: []byte{2}, path: "state"}); err != nil {
			t.Errorf("Commit of snapshot 2: %v", err)
		}
	}()
	<-flushing

	// Snapshot 3 arrives and waits behind that flush.
	second := make(chan struct{})
	go func() {
		defer close(second)
		if err := writer.commit(stateSnapshot{seq: 3, hash: []byte{3}, path: "state"}); err != nil {
			t.Errorf("Commit of snapshot 3: %v", err)
		}
	}()

	// Snapshot 1 reaches the writer LAST, which is what a goroutine descheduled on its way out of
	// the forest hold does. Seeing 3 staged while holding the writer's mutex means the goroutine
	// that staged it has already released the mutex, and the only place it does that is the wait.
	for {
		writer.mutex.Lock()
		if writer.pending != nil && writer.pending.seq == 3 {
			writer.stage(stateSnapshot{seq: 1, hash: []byte{1}, path: "state"})
			writer.mutex.Unlock()
			break
		}
		writer.mutex.Unlock()
		runtime.Gosched()
	}

	close(release)
	<-first
	<-second

	mutex.Lock()
	published := append([]uint64(nil), order...)
	mutex.Unlock()

	for i := 1; i < len(published); i++ {
		if published[i] <= published[i-1] {
			t.Fatalf("The writer published %v: snapshot %d landed after %d, which rolls the state file back", published, published[i], published[i-1])
		}
	}
	if published[len(published)-1] != 3 {
		t.Fatalf("The writer left snapshot %d on the disk, want the newest, 3: %v", published[len(published)-1], published)
	}
}
