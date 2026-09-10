// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// What a long-lived host leaks, if anything.
//
// One test in this repository counted goroutines, on one path. NOTHING counted file descriptors —
// though every Open holds a sidecar lock fd and (when a log path is configured) a log fd, and every
// persist opens a temp file and the directory it syncs. A descriptor leak is the failure a host does
// not see until it has been up for a week and then cannot open anything at all.
package embedded

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

// openDescriptors counts this process's open file descriptors.
//
// /proc/self/fd is the only honest source: Go's runtime opens descriptors of its own (the netpoll
// epoll instance, the /proc entry being read) and a delta against a settled baseline is what a leak
// looks like, not an absolute number.
func openDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd on this platform: %v", err)
	}
	// The directory handle this read is holding is itself one of the entries; it is present in every
	// measurement, so it cancels out of every delta.
	return len(entries)
}

// settle waits for the goroutine count to stop moving, so a measurement is taken against a quiet
// runtime rather than one still winding down from an earlier test.
func settle() {
	last := runtime.NumGoroutine()
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		now := runtime.NumGoroutine()
		if now == last {
			return
		}
		last = now
	}
}

// returnsTo waits for a count produced by measure to come back to a baseline, so a teardown that is
// merely slow is not reported as a leak.
func returnsTo(baseline int, measure func() int) (int, bool) {
	var last int
	for i := 0; i < 100; i++ {
		last = measure()
		if last <= baseline {
			return last, true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return last, false
}

// Many open/close cycles over one path leave neither a goroutine nor a descriptor behind.
//
// Each cycle is a whole runtime: five queue workers, a mutation stream, a state writer, a sidecar
// flock and a state file written and renamed. Fifty of them is nothing for a host that runs for
// weeks, and it is enough for a per-cycle leak of one to be unmistakable.
func TestRepeatedOpenAndCloseLeaksNoGoroutinesOrDescriptors(t *testing.T) {
	cfg := embeddedConfig(t)

	// One warm-up cycle first: the first Open in a process brings up things that are then reused —
	// the netpoller, the logger's machinery — and counting them as a leak would be wrong.
	warm, err := Open(cfg, "warmup")
	if err != nil {
		t.Fatalf("warm-up Open: %v", err)
	}
	if _, err := warm.CreateNode(CreateNodeRequest{Path: "work/warm", Type: "leaf"}); err != nil {
		t.Fatalf("warm-up write: %v", err)
	}
	if err := warm.Close(); err != nil {
		t.Fatalf("warm-up Close: %v", err)
	}

	settle()
	goroutinesBefore := runtime.NumGoroutine()
	fdsBefore := openDescriptors(t)

	const cycles = 50
	for i := 0; i < cycles; i++ {
		handle, err := Open(cfg, "system")
		if err != nil {
			t.Fatalf("cycle %d: Open: %v", i, err)
		}
		if _, err := handle.CreateNode(CreateNodeRequest{
			Path: fmt.Sprintf("work/cycle-%d", i), Type: "leaf",
		}); err != nil {
			t.Fatalf("cycle %d: write: %v", i, err)
		}
		handle.PollMutations(0, 0)
		if err := handle.Close(); err != nil {
			t.Fatalf("cycle %d: Close: %v", i, err)
		}
	}

	settle()
	if after, ok := returnsTo(goroutinesBefore, runtime.NumGoroutine); !ok {
		t.Errorf("%d open/close cycles leaked goroutines: %d before, %d after (%.1f per cycle)",
			cycles, goroutinesBefore, after, float64(after-goroutinesBefore)/cycles)
	}
	if after, ok := returnsTo(fdsBefore, func() int { return openDescriptors(t) }); !ok {
		t.Errorf("%d open/close cycles leaked file descriptors: %d before, %d after (%.1f per cycle). "+
			"Every Open holds a sidecar lock fd and every persist opens a temp file and its directory",
			cycles, fdsBefore, after, float64(after-fdsBefore)/cycles)
	}
}

// A FAILED Open leaks nothing either. It is the path a host retries in a loop when a sibling process
// holds the file, so a descriptor or a goroutine per attempt is a leak with a retry loop behind it.
func TestRepeatedlyRefusedOpenLeaksNothing(t *testing.T) {
	cfg := embeddedConfig(t)
	key, err := canonicalPath(cfg)
	if err != nil {
		t.Fatalf("canonicalPath: %v", err)
	}

	// A rival file description holds the sidecar, so every Open below is refused at the flock —
	// before a forest, a queue or a writer is built.
	blocker, err := acquireLock(key)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	defer releaseLock(blocker)

	if _, err := Open(cfg, "warmup"); err == nil {
		t.Fatal("Open succeeded against a held path")
	}
	settle()
	goroutinesBefore := runtime.NumGoroutine()
	fdsBefore := openDescriptors(t)

	const attempts = 50
	for i := 0; i < attempts; i++ {
		handle, err := Open(cfg, "system")
		if err == nil {
			handle.Close()
			t.Fatalf("attempt %d: Open succeeded against a held path", i)
		}
	}

	settle()
	if after, ok := returnsTo(goroutinesBefore, runtime.NumGoroutine); !ok {
		t.Errorf("%d refused Opens leaked goroutines: %d before, %d after", attempts, goroutinesBefore, after)
	}
	if after, ok := returnsTo(fdsBefore, func() int { return openDescriptors(t) }); !ok {
		t.Errorf("%d refused Opens leaked file descriptors: %d before, %d after — the sidecar is "+
			"opened before the flock is attempted and must be closed when the flock fails",
			attempts, fdsBefore, after)
	}
}

// Many paths open AT ONCE cost descriptors in proportion, and give every one of them back.
//
// This is the shape a host acting over several archives has, and it is where a per-runtime leak
// shows as an absolute number rather than as drift: fifty live runtimes hold fifty sidecar locks.
func TestManyLiveRuntimesReleaseEveryDescriptor(t *testing.T) {
	settle()
	goroutinesBefore := runtime.NumGoroutine()
	fdsBefore := openDescriptors(t)

	const runtimes = 25
	handles := make([]*Handle, runtimes)
	for i := range handles {
		handle, err := Open(embeddedConfig(t), "system")
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		handles[i] = handle
	}

	// While they are all live, the descriptors are genuinely held — a count that did NOT rise would
	// mean the measurement is not measuring anything.
	if held := openDescriptors(t); held <= fdsBefore {
		t.Fatalf("%d live runtimes hold %d descriptors against a baseline of %d; each one holds a "+
			"sidecar flock, so this count must rise", runtimes, held, fdsBefore)
	}

	for i, handle := range handles {
		if err := handle.Close(); err != nil {
			t.Fatalf("Close %d: %v", i, err)
		}
	}

	settle()
	if after, ok := returnsTo(goroutinesBefore, runtime.NumGoroutine); !ok {
		t.Errorf("%d runtimes left goroutines behind: %d before, %d after", runtimes, goroutinesBefore, after)
	}
	if after, ok := returnsTo(fdsBefore, func() int { return openDescriptors(t) }); !ok {
		t.Errorf("%d runtimes left descriptors behind: %d before, %d after (%.1f per runtime)",
			runtimes, fdsBefore, after, float64(after-fdsBefore)/runtimes)
	}
}

// A write-heavy runtime does not accumulate descriptors as it persists. Every persist opens a temp
// file and the directory it fsyncs, and both are transient — a hundred writes must cost the same
// descriptors as one.
func TestRepeatedPersistsHoldNoExtraDescriptors(t *testing.T) {
	cfg := embeddedConfig(t)
	handle, err := Open(cfg, "alice")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer handle.Close()

	if _, err := handle.CreateNode(CreateNodeRequest{Path: "work/warm", Type: "leaf"}); err != nil {
		t.Fatalf("warm-up write: %v", err)
	}
	settle()
	fdsBefore := openDescriptors(t)

	const writes = 100
	for i := 0; i < writes; i++ {
		if _, err := handle.CreateNode(CreateNodeRequest{
			Path: fmt.Sprintf("work/n%d", i), Type: "leaf",
		}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	if after, ok := returnsTo(fdsBefore, func() int { return openDescriptors(t) }); !ok {
		t.Errorf("%d persists left %d descriptors open against a baseline of %d; the temp file and "+
			"the directory fsync are meant to be transient", writes, after, fdsBefore)
	}
}
