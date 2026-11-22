// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/types"
)

// The cold writer's image: a snapshot is the state at the sequence it names, and the forest is free
// while it is encoded. Run under -race.

// coldWait is how long a read or a commit may take while an encode is held open before the test
// calls it blocked. Nothing in them waits on the encode, so it is generous.
const coldWait = 10 * time.Second

// createColdNode creates one leaf under cold/ through the one write path and answers the sequence of
// the record that holds it.
func createColdNode(server *Server, userID, name string) (uint64, error) {
	commit, err := server.changeForestOp(engineWriteOp(), func() error {
		_, err := server.createNodePath("cold/"+name, core.LeafNode, userID)
		return err
	})
	return commit.Seq, err
}

// documentOnDisk is the plaintext document the state file holds, checked against the hash in front
// of it. It reads the file alone: the load path's reader also resets the live server's read token.
func documentOnDisk(t *testing.T, server *Server) []byte {
	t.Helper()
	file, err := os.Open(server.statePath())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := stateMagicLevel(file); err != nil {
		t.Fatal(err)
	}
	hash := make([]byte, sha256.Size)
	if _, err := io.ReadFull(file, hash); err != nil {
		t.Fatal(err)
	}
	data, err := readCappedGzip(file, maxDecompressedState)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(data); !bytes.Equal(sum[:], hash) {
		t.Fatal("the state file's hash does not vouch for its document")
	}
	return data
}

// coldNamesOnDisk is the sequence the state file names and the names of the cold/ leaves it holds.
func coldNamesOnDisk(t *testing.T, server *Server) (uint64, []string) {
	t.Helper()
	table, err := decodeTable(documentOnDisk(t, server))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, record := range table.records {
		if strings.HasPrefix(record.Node.Name, "c-") {
			names = append(names, record.Node.Name)
		}
	}
	sort.Strings(names)
	return table.LogSequence, names
}

// expectedState is the state document encodeStateAt writes for the forest as it is now.
func expectedState(server *Server) (uint64, []byte, error) {
	var seq uint64
	var data []byte
	var err error
	server.readForest(func() {
		seq = server.tier.log.LastStaged()
		data, err = encodeStateAt(server.forest, seq)
	})
	return seq, data, err
}

// within runs work and fails the test when it has not returned in coldWait.
func within(t *testing.T, what string, work func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		work()
	}()
	select {
	case <-done:
	case <-time.After(coldWait):
		t.Fatalf("%s did not finish while the snapshot was encoding: it waits on the forest", what)
	}
}

// holdEncode makes the next cold snapshot stop between its capture and its encode, and answers a
// channel that is closed when it has stopped there and the function that lets it go on.
func holdEncode(server *Server) (<-chan struct{}, func()) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	server.tier.beforeEncode = func() {
		once.Do(func() { close(entered) })
		<-release
	}
	var released sync.Once
	return entered, func() { released.Do(func() { close(release) }) }
}

// A read and a commit both finish while a cold snapshot is encoding, and the file the snapshot
// publishes is the state at the sequence it names — byte for byte what encodeStateAt writes for the
// forest at that sequence — and not the commit made during it, which the log holds.
func TestAColdSnapshotLeavesReadsAndCommitsFreeWhileItEncodes(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	token := storeAdmin(t, server)
	userID := adminID(t, server)
	seedNodes(t, server, 200)
	if status, body := titleWrite(t, server, token, 7, "before"); status != http.StatusOK {
		t.Fatalf("write: %d %v", status, body)
	}
	captured, expected, err := expectedState(server)
	if err != nil {
		t.Fatal(err)
	}

	entered, release := holdEncode(server)
	defer release()
	result := make(chan error, 1)
	var published uint64
	go func() {
		var err error
		published, err = server.snapshotCold()
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(coldWait):
		t.Fatal("the snapshot never reached its encode")
	}

	within(t, "a read", func() { _ = entriesOn(server, scaleNode(7)) })
	var during uint64
	within(t, "a commit", func() { during, err = createColdNode(server, userID, "c-during") })
	if err != nil || during <= captured {
		t.Fatalf("the commit during the encode: seq %d after %d, %v", during, captured, err)
	}
	release()
	if err := <-result; err != nil || published != captured {
		t.Fatalf("snapshot: published %d, captured %d, %v", published, captured, err)
	}
	if got := documentOnDisk(t, server); !bytes.Equal(got, expected) {
		t.Fatalf("the state file is not the state at %d: %d bytes, expected %d", captured, len(got), len(expected))
	}

	reopened := reopenWith(t, server, config, false)
	if _, err := reopened.getNodeFromPath("cold/c-during"); err != nil {
		t.Fatalf("the commit made during the snapshot was not recovered: %v", err)
	}
}

// coldLedger is which cold/ leaf each acknowledged commit created, by the sequence of its record.
type coldLedger struct {
	mutex sync.Mutex
	names map[uint64]string
}

func (ledger *coldLedger) note(seq uint64, name string) {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()
	ledger.names[seq] = name
}

// through is the names of the leaves created by records at or below seq, sorted.
func (ledger *coldLedger) through(seq uint64) []string {
	ledger.mutex.Lock()
	defer ledger.mutex.Unlock()
	names := []string{}
	for at, name := range ledger.names {
		if at <= seq {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// createColdUntil is one writer: it creates its own leaves, one durable write each, until stop.
func createColdUntil(t *testing.T, server *Server, userID string, w int, stop <-chan struct{}, ledger *coldLedger) {
	for i := 0; ; i++ {
		select {
		case <-stop:
			return
		default:
		}
		name := fmt.Sprintf("c-w%d-%05d", w, i)
		seq, err := createColdNode(server, userID, name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			return
		}
		ledger.note(seq, name)
	}
}

// coldSnapshot is what one snapshot's file held: the sequence it names and its cold/ leaves.
type coldSnapshot struct {
	seq    uint64
	named  uint64
	leaves []string
}

// snapshotColdFor takes cold snapshots back to back for a while and answers what each file held.
func snapshotColdFor(t *testing.T, server *Server, length time.Duration) []coldSnapshot {
	t.Helper()
	taken := []coldSnapshot{}
	for deadline := time.Now().Add(length); time.Now().Before(deadline); {
		seq, err := server.snapshotCold()
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		named, leaves := coldNamesOnDisk(t, server)
		taken = append(taken, coldSnapshot{seq: seq, named: named, leaves: leaves})
	}
	return taken
}

// Under writers that never stop, every snapshot holds exactly the leaves whose records are at or
// below the sequence it names: none created after it, none missing before it. A torn image — part
// of a later commit, or a commit lost between capture and encode — fails here. The files are
// checked once the writers have stopped, when the ledger knows every commit's sequence.
func TestEveryColdSnapshotIsTheStateAtItsSequence(t *testing.T) {
	config := tieredConfig(t, types.HotSyncNone)
	server := newServerWith(t, config)
	userID := adminID(t, server)
	seedNodes(t, server, 300)

	ledger := &coldLedger{names: map[uint64]string{}}
	stop := make(chan struct{})
	var group sync.WaitGroup
	for w := 0; w < 4; w++ {
		group.Add(1)
		go func(w int) {
			defer group.Done()
			createColdUntil(t, server, userID, w, stop, ledger)
		}(w)
	}
	taken := snapshotColdFor(t, server, 2*time.Second)
	close(stop)
	group.Wait()
	for _, snapshot := range taken {
		want := ledger.through(snapshot.seq)
		if snapshot.named != snapshot.seq || strings.Join(snapshot.leaves, ",") != strings.Join(want, ",") {
			t.Fatalf("the snapshot at %d (file names %d) holds %d leaves, the log through it %d",
				snapshot.seq, snapshot.named, len(snapshot.leaves), len(want))
		}
	}
	if total := len(ledger.through(math.MaxUint64)); len(taken) == 0 || total == 0 {
		t.Fatal("nothing ran")
	}
	t.Logf("%d snapshots checked against %d commits", len(taken), len(ledger.through(math.MaxUint64)))
}

// A change the codec cannot encode is refused and logs nothing, and it leaves the cache where the
// last record left it: the next commit logs everything the refused one changed, and the cold writer
// never writes a change the log does not hold. Before, the walk had already cached the nodes it
// passed, so the next record left them out and a restart lost them.
func TestAChangeThatCouldNotBeEncodedIsLoggedByTheNextCommit(t *testing.T) {
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	seedNodes(t, server, 3)
	if _, err := server.snapshotCold(); err != nil {
		t.Fatal(err)
	}
	setMetadata := func(path, key string, value interface{}) func() error {
		return func() error {
			node, err := server.getNodeFromPath(path)
			if err != nil {
				return err
			}
			if node.Metadata == nil {
				node.Metadata = map[string]interface{}{}
			}
			node.Metadata[key] = value
			return nil
		}
	}
	refused := func() error {
		// "scale" is walked before its leaves, so it is encoded before the leaf that cannot be.
		if err := setMetadata("scale", "title", "kept")(); err != nil {
			return err
		}
		return setMetadata(scaleNode(1), "bad", math.NaN())()
	}
	if _, err := server.changeForestOp(extension.WriteOp{Key: "refused"}, refused); err == nil {
		t.Fatal("a NaN was encoded")
	}
	if seq, err := server.snapshotCold(); err != nil || seq != server.tier.lastCold.Load() {
		t.Fatalf("a refused change moved the snapshot: %d %v", seq, err)
	}
	if err := server.changeForest(setMetadata(scaleNode(1), "bad", "fixed")); err != nil {
		t.Fatal(err)
	}

	reopened := reopenWith(t, server, config, false)
	node, err := reopened.getNodeFromPath("scale")
	if err != nil || node.Metadata["title"] != "kept" {
		t.Fatalf("the change the refused commit made, logged by the next one, was lost: %v %v", node, err)
	}
}

// A cache entry that holds no encoding (the tracked path on the pdl branches writes one) is not
// written as `null`, which the loader skips: the cold writer encodes the forest instead, so the file
// holds the node and is byte for byte the forest at its sequence.
func TestANilCacheEntryFallsBackToEncodingTheForest(t *testing.T) {
	config := tieredConfig(t, types.HotSyncNone)
	server := newServerWith(t, config)
	seedNodes(t, server, 5)
	if _, err := server.snapshotCold(); err != nil {
		t.Fatal(err)
	}
	if _, err := createColdNode(server, adminID(t, server), "c-due"); err != nil {
		t.Fatal(err)
	}
	victim := ""
	server.readForest(func() {
		for id := range server.tier.cache {
			if id != server.tier.root {
				victim = id
				break
			}
		}
	})
	server.forestMutex.Lock()
	server.tier.cache[victim] = nil
	server.forestMutex.Unlock()
	captured, expected, err := expectedState(server)
	if err != nil {
		t.Fatal(err)
	}

	if seq, err := server.snapshotCold(); err != nil || seq != captured {
		t.Fatalf("snapshot: %d (want %d) %v", seq, captured, err)
	}
	document := documentOnDisk(t, server)
	table, err := decodeTable(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, held := table.records[victim]; !held || !bytes.Equal(document, expected) {
		t.Fatalf("node %s held: %v; the file is not the forest at %d", victim, held, captured)
	}
}
