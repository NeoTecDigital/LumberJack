// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The runtime's lifecycle at its edges: a lock held by ANOTHER PROCESS, the registry under
// concurrent Open and Close, and what a handle does after the runtime under it is gone.
//
// The whole sidecar-flock design rested on a same-process approximation — a second open file
// description, which conflicts identically but is not the thing being claimed. Nothing in this
// repository spawned a process, so "another process holding the same file is refused" had never
// been observed. It is observed here, by re-executing this test binary.
package embedded

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/types"
)

// lockHolderEnv names the state directory a child process is to open and hold. Its presence is what
// turns this test binary into the holder instead of a test run.
const lockHolderEnv = "LUMBERJACK_TEST_LOCK_HOLDER_DIR"

// lockHolderReady is what the child prints once it has the lock, so the parent waits on the fact
// rather than on a sleep.
const lockHolderReady = "HELD"

// TestMain re-executes this binary as a lock HOLDER when the environment says so.
//
// It is the whole subprocess harness: `exec.Command(os.Args[0])` with the variable set runs the
// child below and never reaches m.Run, so no test name is spent on it and the child needs no
// separate program to build.
func TestMain(m *testing.M) {
	if dir := os.Getenv(lockHolderEnv); dir != "" {
		lockHolderMain(dir)
		return
	}
	os.Exit(m.Run())
}

// lockHolderMain opens a runtime over a directory, announces that it holds the lock, and keeps
// holding it until its standard input closes. The parent controls the release by closing the pipe,
// so the hold lasts exactly as long as the parent needs and not one scheduling accident longer.
func lockHolderMain(dir string) {
	handle, err := Open(configOver(dir), "holder")
	if err != nil {
		fmt.Fprintf(os.Stderr, "child: Open: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(lockHolderReady)
	os.Stdout.Sync()

	// Block until the parent closes the pipe.
	_, _ = os.Stdin.Read(make([]byte, 1))

	if err := handle.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "child: Close: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// configOver is the config both the parent and the child build for one state directory, so the two
// processes provably name the same file.
func configOver(dir string) Config {
	return Config{Process: types.ProcessInfo{Name: "embedded_test", DatabasePath: dir}}
}

// ANOTHER PROCESS holding the path is refused ErrLocked — the status the C ABI reports as LJ_LOCKED,
// which no test had ever produced. And the refusal LIFTS when that process lets go: a lock that is
// never released is as broken as one that never held.
func TestASecondProcessIsRefusedTheSamePath(t *testing.T) {
	dir := t.TempDir()
	cfg := configOver(dir)

	child := exec.Command(os.Args[0])
	child.Env = append(os.Environ(), lockHolderEnv+"="+dir)
	child.Stderr = os.Stderr

	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := child.Start(); err != nil {
		t.Fatalf("start the holder process: %v", err)
	}
	defer func() {
		stdin.Close()
		child.Wait()
	}()

	// Wait for the child to actually hold it, rather than sleeping and hoping.
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- strings.TrimSpace(scanner.Text())
			return
		}
		ready <- ""
	}()
	select {
	case line := <-ready:
		if line != lockHolderReady {
			t.Fatalf("the holder process announced %q, want %q", line, lockHolderReady)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the holder process never announced that it had the lock")
	}

	// THE ASSERTION: a genuinely separate process holds the sidecar, and this one is refused.
	rival, err := Open(cfg, "rival")
	if err == nil {
		rival.Close()
		t.Fatal("Open succeeded while ANOTHER PROCESS held the path: two runtimes over one state " +
			"file is last-writer-wins, and the other's work is gone silently")
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("Open against a held path reported %v, want ErrLocked (the FFI's LJ_LOCKED)", err)
	}

	// And the refusal is not permanent: when the holder goes, the path is available. The successor
	// acts as the system user because the holder's Open seeded one — see
	// TestReopeningASeededForestNoLongerActsAsSystem.
	stdin.Close()
	if err := child.Wait(); err != nil {
		t.Fatalf("the holder process exited badly: %v", err)
	}

	handle, err := Open(cfg, internal.SystemUserID)
	if err != nil {
		t.Fatalf("Open after the holder released the path: %v", err)
	}
	defer handle.Close()
	if _, err := handle.CreateNode(CreateNodeRequest{Path: "work/after", Type: "leaf"}); err != nil {
		t.Fatalf("the successor could not write: %v", err)
	}
}

// A forest the first process wrote is what the second one reads. The lock is not the only thing
// crossing the process boundary — the state file is — and a handover that loses the forest would
// satisfy the test above.
func TestAPathHandedOverBetweenProcessesKeepsItsForest(t *testing.T) {
	dir := t.TempDir()
	cfg := configOver(dir)

	first, err := Open(cfg, "first")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := first.CreateNode(CreateNodeRequest{Path: "work/handover", Type: "leaf"}); err != nil {
		t.Fatalf("write before the handover: %v", err)
	}
	if _, err := first.StartEvent(StartEventRequest{Path: "work/handover", EventID: "e1"}); err != nil {
		t.Fatalf("start before the handover: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := Open(cfg, internal.SystemUserID)
	if err != nil {
		t.Fatalf("reopen after the last Close: %v", err)
	}
	defer second.Close()

	if _, err := second.AppendToEvent(AppendEventRequest{
		Path: "work/handover", EventID: "e1", Content: "after the handover",
	}); err != nil {
		t.Fatalf("the event the first runtime started is not there after a reopen: %v", err)
	}
}

// Deleting the sidecar beside an existing state file is REFUSED a new lock, which closes the
// two-live-runtimes hole it used to open.
//
// A flock follows the inode. Unlink the sidecar while a process holds it and that holder is left
// locking an orphaned inode; the next acquire would mint a FRESH sidecar and take an uncontended lock
// on a new inode, so the two processes would each believe they held the path while writing the same
// state file last-writer-wins. acquireLock now refuses to create a sidecar where a state file already
// exists — from the filesystem a deleted-while-held sidecar cannot be told from one that was never
// there, so failing closed is the only defence.
//
// This REPLACES TestDeletingTheSidecarWhileHeldDefeatsTheLock, which recorded the hole: the rival
// acquired, the two locks landed on different inodes, and a second PROCESS opened a whole live runtime
// over the same file.
func TestDeletingTheSidecarBesideAStateFileRefusesANewLock(t *testing.T) {
	dir := t.TempDir()
	cfg := configOver(dir)
	key, err := canonicalPath(cfg)
	if err != nil {
		t.Fatalf("canonicalPath: %v", err)
	}

	// A REAL runtime with a REAL forest, so the state file the sidecar guards genuinely exists.
	holder, err := Open(cfg, "holder")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer holder.Close()
	if _, err := holder.CreateNode(CreateNodeRequest{Path: "work/precious", Type: "leaf"}); err != nil {
		t.Fatalf("seed the forest: %v", err)
	}
	if _, err := os.Stat(key); err != nil {
		t.Fatalf("the state file was never written: %v", err)
	}

	// CONTROL: while the sidecar is where the runtime left it, a rival is refused at the flock.
	if rival, err := acquireLock(key); err == nil {
		releaseLock(rival)
		t.Fatal("a rival took the path while the sidecar was held and present")
	} else if !errors.Is(err, ErrLocked) {
		t.Fatalf("a contended acquire reported %v, want ErrLocked", err)
	}

	if err := os.Remove(lockPathFor(key)); err != nil {
		t.Fatalf("remove the sidecar: %v", err)
	}

	// THE FIX: with the sidecar gone but the state file present, a new acquire is REFUSED rather than
	// minting a rival on a fresh inode. It answers ErrLocked — the fail-closed status a caller backs
	// off on — so the holder above stays the only lock on the path.
	if rival, err := acquireLock(key); err == nil {
		releaseLock(rival)
		t.Fatal("acquireLock minted a fresh sidecar beside an existing state file whose sidecar was " +
			"deleted; that is a second live runtime over one state file")
	} else if !errors.Is(err, ErrLocked) {
		t.Fatalf("acquiring beside a deleted sidecar reported %v, want ErrLocked", err)
	}

	// And a genuinely separate PROCESS is refused too: its own Open reaches the same refusal, so it
	// cannot bring up a rival runtime over the file. It exits non-zero without ever announcing HELD.
	child := exec.Command(os.Args[0])
	child.Env = append(os.Environ(), lockHolderEnv+"="+dir)
	child.Stderr = os.Stderr
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := child.Start(); err != nil {
		t.Fatalf("start the second process: %v", err)
	}

	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- strings.TrimSpace(scanner.Text())
			return
		}
		ready <- ""
	}()
	select {
	case line := <-ready:
		if line == lockHolderReady {
			t.Fatal("a second process opened the path whose sidecar was deleted: two live runtimes " +
				"over one state file")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the second process neither announced nor exited")
	}

	if err := child.Wait(); err == nil {
		t.Fatal("the second process exited cleanly; it should have been refused the locked path")
	}
}

// The registry is what makes a second Open in ONE process share the first's runtime rather than
// deadlock against its own flock. Concurrently, that has to hold for every opener at once: one
// runtime, one engine, and a refcount that is exactly the number of handles.
func TestConcurrentOpenOfOnePathSharesOneRuntime(t *testing.T) {
	cfg := embeddedConfig(t)

	const openers = 32
	handles := make([]*Handle, openers)
	errs := make([]error, openers)

	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for i := 0; i < openers; i++ {
		done.Add(1)
		go func(n int) {
			defer done.Done()
			start.Wait()
			handles[n], errs[n] = Open(cfg, fmt.Sprintf("principal-%d", n))
		}(i)
	}
	start.Done()
	done.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Open %d failed: %v — a second Open in one process must share the "+
				"first's runtime, never contend for its own flock", i, err)
		}
	}
	for i := 1; i < openers; i++ {
		if handles[i].runtime != handles[0].runtime {
			t.Fatalf("concurrent Open %d built a rival runtime over the same path", i)
		}
	}
	if got := refsOf(handles[0].runtime); got != openers {
		t.Fatalf("refs = %d after %d concurrent Opens, want %d", got, openers, openers)
	}

	// And they close down to nothing, exactly once.
	for i, handle := range handles {
		if err := handle.Close(); err != nil {
			t.Fatalf("Close %d: %v", i, err)
		}
	}
	if inRegistry(handles[0].runtime.path) {
		t.Fatal("the runtime outlived its last handle")
	}
}

// An Open racing the LAST Close must land on one side or the other and never in between: either it
// finds the runtime still in the registry and takes a reference, or it finds the registry empty and
// builds a fresh one. What it must never do is fail — an ErrLocked here would mean the closing
// runtime released the registry entry before its flock, and an in-process opener would be refused by
// a lock it is supposed to be sharing.
func TestOpenRacingTheLastCloseNeverFails(t *testing.T) {
	for round := 0; round < 60; round++ {
		cfg := embeddedConfig(t)

		closing, err := Open(cfg, "closer")
		if err != nil {
			t.Fatalf("round %d: seed Open: %v", round, err)
		}

		var ready sync.WaitGroup
		var finished sync.WaitGroup
		ready.Add(2)
		finished.Add(2)

		var closeErr, openErr error
		var opened *Handle

		go func() {
			defer finished.Done()
			ready.Done()
			ready.Wait()
			closeErr = closing.Close()
		}()
		go func() {
			defer finished.Done()
			ready.Done()
			ready.Wait()
			opened, openErr = Open(cfg, internal.SystemUserID)
		}()
		finished.Wait()

		if closeErr != nil {
			t.Fatalf("round %d: the last Close reported %v", round, closeErr)
		}
		if openErr != nil {
			t.Fatalf("round %d: an Open racing the last Close was refused with %v — in-process "+
				"openers must never contend for the path's flock", round, openErr)
		}

		// Whichever side it landed on, the handle is usable and its runtime is the registered one.
		if _, err := opened.CreateNode(CreateNodeRequest{Path: "work/raced", Type: "leaf"}); err != nil {
			t.Fatalf("round %d: the handle from the raced Open cannot write: %v", round, err)
		}
		if !inRegistry(opened.runtime.path) {
			t.Fatalf("round %d: the raced Open returned a handle on an unregistered runtime", round)
		}
		if err := opened.Close(); err != nil {
			t.Fatalf("round %d: closing the raced handle: %v", round, err)
		}
		if inRegistry(opened.runtime.path) {
			t.Fatalf("round %d: the runtime outlived its last handle", round)
		}
	}
}

// A CLOSED handle still READS from the forest in memory, but REFUSES every write.
//
// The reads answer from the forest still resident in memory — harmless, they touch no file and no
// lock. The writes do not: a Close tears the runtime down on the last reference and RELEASES the
// sidecar flock, so a write that ran on afterwards would reach the state file the released lock no
// longer guards, under a path another process may by then legitimately hold. Each of the five
// mutating methods now answers ErrClosed.
//
// This REPLACES TestClosedHandleStillReadsAndStillWrites, which recorded the hole — that all five
// writes ran to completion and reached the disk after Close. The C ABI never exposed it (ic_lj_close
// drops the token, so a later data call is LJ_BAD_HANDLE); it was reachable from any in-process Go
// embedder, and from the Rust engine, which consume embedded directly.
func TestAClosedHandleStillReadsButRefusesEveryWrite(t *testing.T) {
	cfg := embeddedConfig(t)
	handle, err := Open(cfg, "alice")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := handle.CreateNode(CreateNodeRequest{Path: "work/before", Type: "leaf"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close is idempotent, and the epoch is a value the handle already holds.
	if err := handle.Close(); err != nil {
		t.Fatalf("a second Close reported %v, want nil", err)
	}
	if handle.Epoch() == 0 {
		t.Error("Epoch after Close is 0; it is this run's numbering and does not depend on the runtime")
	}

	// THE READS still answer from the forest still in memory.
	if view := handle.Forest(); view.Name == "" {
		t.Error("Forest after Close returned an unnamed view")
	}
	if _, err := handle.Query(QueryRequest{Select: "nodes"}); err != nil {
		t.Errorf("Query after Close reported %v; a read touches only memory and is left to answer", err)
	}
	if _, err := handle.Aggregate(AggregateRequest{Select: "nodes", Group: []string{"node_path"}}); err != nil {
		t.Errorf("Aggregate after Close reported %v; a read touches only memory and is left to answer", err)
	}

	// StatusOf and a blocked poll notice the teardown through the worker pool and the shutdown signal
	// they route through — behaviour this fix does not change, asserted so the read story stays whole.
	if _, err := handle.StatusOf("work/before"); err == nil {
		t.Error("StatusOf after Close answered; the worker pool it reads through has been stopped")
	}
	polled := make(chan struct{})
	go func() { handle.PollMutations(0, 10*time.Second); close(polled) }()
	select {
	case <-polled:
	case <-time.After(2 * time.Second):
		t.Error("PollMutations after Close blocked; the runtime's shutdown signal is closed")
	}

	// THE WRITES. Every one of the five mutating methods refuses with ErrClosed. Each targets a node
	// seeded BEFORE Close, so without the guard each would genuinely run and land — the refusal is the
	// fix, not a missing node.
	if _, err := handle.CreateNode(CreateNodeRequest{Path: "work/after-close", Type: "leaf"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("CreateNode after Close reported %v, want ErrClosed — a closed handle must not write "+
			"behind the flock its Close released", err)
	}
	if _, err := handle.StartEvent(StartEventRequest{Path: "work/before", EventID: "e1"}); !errors.Is(err, ErrClosed) {
		t.Errorf("StartEvent after Close reported %v, want ErrClosed", err)
	}
	if _, err := handle.AppendToEvent(AppendEventRequest{
		Path: "work/before", EventID: "e1", Content: "written after shutdown",
	}); !errors.Is(err, ErrClosed) {
		t.Errorf("AppendToEvent after Close reported %v, want ErrClosed", err)
	}
	if _, err := handle.EndEvent(EndEventRequest{Path: "work/before", EventID: "e1"}); !errors.Is(err, ErrClosed) {
		t.Errorf("EndEvent after Close reported %v, want ErrClosed", err)
	}
	if _, err := handle.PlanEvent(PlanEventRequest{
		Path: "work/before", EventID: "p1",
		StartTime: "2030-01-01T00:00:00Z", EndTime: "2030-01-01T01:00:00Z",
	}); !errors.Is(err, ErrClosed) {
		t.Errorf("PlanEvent after Close reported %v, want ErrClosed", err)
	}

	// And NOTHING reached the disk: a fresh runtime over the same path does not see the refused write.
	successor, err := Open(cfg, internal.SystemUserID)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer successor.Close()
	if _, err := successor.StatusOf("work/after-close"); err == nil {
		t.Fatal("a fresh runtime sees work/after-close: a write refused through the closed handle " +
			"still reached the state file")
	}
}

// The last Close RELEASES the flock — a rival takes the path at once — AND the closed handle refuses
// to write to it, so there is exactly one writer.
//
// This REPLACES TestTheLastCloseReleasesTheFlockWhileWritesRemainPossible, whose name enshrined the
// hole: the release was always real, but the closed handle went on writing the state file while
// another holder believed it held the path exclusively.
func TestTheLastCloseReleasesTheFlockAndTheClosedHandleRefusesToWrite(t *testing.T) {
	cfg := embeddedConfig(t)
	key, err := canonicalPath(cfg)
	if err != nil {
		t.Fatalf("canonicalPath: %v", err)
	}

	handle, err := Open(cfg, "alice")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The flock IS released: a rival takes the path the instant the last handle closes.
	rival, err := acquireLock(key)
	if err != nil {
		t.Fatalf("the last Close did not release the flock: %v", err)
	}
	defer releaseLock(rival)

	// And the closed handle REFUSES to write to it, so the rival above is the only writer.
	if _, err := handle.CreateNode(CreateNodeRequest{Path: "work/unlocked", Type: "leaf"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("CreateNode through a closed handle reported %v, want ErrClosed — it would otherwise "+
			"write the state file while the rival holds the path's lock", err)
	}
}

// The default-system latch, at the boundary that surprises an embedder: the FIRST runtime over an
// empty forest seeds the `system` user and acts as it whatever principal it was given — and every
// runtime after that finds a forest with users in it, so the default is not consulted and each
// handle acts as its own name. The same call that worked before the process restarted is refused
// after it.
//
// It is not a hole — nothing is granted that "system" would not already grant — but it is the reason
// a reopen must name the system user, and nothing stated it.
func TestReopeningASeededForestNoLongerActsAsSystem(t *testing.T) {
	cfg := embeddedConfig(t)

	first, err := Open(cfg, "whoever")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if !first.runtime.systemDefault {
		t.Fatal("the first Open of an empty forest did not take the system default")
	}
	if _, err := first.CreateNode(CreateNodeRequest{Path: "work/seeded", Type: "leaf"}); err != nil {
		t.Fatalf("the first runtime could not write: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The SAME principal, the same path, a fresh runtime: the seed is now a real user, so the
	// default is not consulted and "whoever" holds nothing.
	second, err := Open(cfg, "whoever")
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer second.Close()
	if second.runtime.systemDefault {
		t.Fatal("a runtime over a forest that already has users took the system default")
	}
	if _, err := second.CreateNode(CreateNodeRequest{Path: "work/second", Type: "leaf"}); err == nil {
		t.Fatal("an arbitrary principal wrote to a forest that already has users")
	}

	// Naming the system user explicitly is what a reopening embedder must do.
	asSystem, err := Open(cfg, internal.SystemUserID)
	if err != nil {
		t.Fatalf("Open as the system user: %v", err)
	}
	defer asSystem.Close()
	if _, err := asSystem.CreateNode(CreateNodeRequest{Path: "work/second", Type: "leaf"}); err != nil {
		t.Fatalf("the system user could not write to its own seeded forest: %v", err)
	}
}
