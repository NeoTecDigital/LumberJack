// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The Step 3 gate: the two things the embedded layer owns that nothing owned before — a runtime
// refcounted by path, and a flock over that path — plus a Close that returns a blocked poll at once.
package embedded

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/types"
)

// embeddedConfig is a config over a private temp directory, so each test opens an isolated path and
// the package-global registry never carries state between tests.
func embeddedConfig(t *testing.T) types.ServerConfig {
	t.Helper()
	return types.ServerConfig{
		Process: types.ProcessInfo{Name: "embedded_test", DatabasePath: t.TempDir()},
	}
}

func TestOpenSharesOneRuntimeAndLastCloseShutsDown(t *testing.T) {
	cfg := embeddedConfig(t)

	alice, err := Open(cfg, "alice")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	bob, err := Open(cfg, "bob")
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}

	// Two Opens of one path share one runtime and one engine — the principal is what differs.
	if alice.runtime != bob.runtime {
		t.Fatal("two Opens on one path did not share a runtime")
	}
	if alice.runtime.server != bob.runtime.server {
		t.Fatal("the shared runtime holds two different *internal.Server")
	}
	if alice.principal == bob.principal {
		t.Fatal("the two handles were bound to the same principal")
	}
	if got := refsOf(alice.runtime); got != 2 {
		t.Fatalf("refs = %d, want 2", got)
	}

	// The first Close drops a reference but does NOT tear the runtime down.
	if err := alice.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if got := refsOf(bob.runtime); got != 1 {
		t.Fatalf("refs after one Close = %d, want 1", got)
	}
	if !inRegistry(bob.runtime.path) {
		t.Fatal("the runtime left the registry while a handle was still open")
	}

	// The last Close tears it down: it leaves the registry and its shutdown signal is closed.
	if err := bob.Close(); err != nil {
		t.Fatalf("last Close: %v", err)
	}
	if inRegistry(bob.runtime.path) {
		t.Fatal("the last Close did not remove the runtime from the registry")
	}
	select {
	case <-bob.runtime.closed:
	default:
		t.Fatal("the last Close did not close the runtime's shutdown signal")
	}
}

func TestLockSurvivesAPersistAndRefusesASecondHolder(t *testing.T) {
	cfg := embeddedConfig(t)
	key, err := canonicalPath(cfg)
	if err != nil {
		t.Fatalf("canonicalPath: %v", err)
	}

	holder, err := Open(cfg, "alice")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer holder.Close()

	// Reproduce a persist. internal/file.go writes a temp file and RENAMES it over the state path,
	// replacing that path's inode — the exact operation that orphans a lock taken on the state file
	// itself, because a flock follows the inode. The sidecar lock is on <state>.lock and must be
	// untouched. A test that never writes proved nothing; this is the write.
	replaceStateFile(t, key)

	// A rival — another process in production; a second open-file description here, which conflicts
	// identically — must still be refused after the write.
	rival, err := acquireLock(key)
	if err == nil {
		releaseLock(rival)
		t.Fatal("the lock did not survive a persist: a rival took the path after a state-file replacement")
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("rival after a persist got %v, want ErrLocked", err)
	}
}

// replaceStateFile does to the state path exactly what a persist does: a fresh temp file renamed over
// it, so the path is backed by a new inode afterwards.
func replaceStateFile(t *testing.T, statePath string) {
	t.Helper()
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, []byte("a persisted forest"), 0o644); err != nil {
		t.Fatalf("write temp state: %v", err)
	}
	if err := os.Rename(tmp, statePath); err != nil {
		t.Fatalf("rename over state path: %v", err)
	}
}

func TestDoubleCloseDoesNotStealAnotherHandlesReference(t *testing.T) {
	cfg := embeddedConfig(t)

	alice, err := Open(cfg, "alice")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	bob, err := Open(cfg, "bob")
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer bob.Close()

	// alice closes twice. The second is a no-op returning nil — NOT a second decref that would tear
	// down the runtime bob still holds.
	if err := alice.Close(); err != nil {
		t.Fatalf("alice first Close: %v", err)
	}
	if err := alice.Close(); err != nil {
		t.Fatalf("alice second Close returned an error, want nil: %v", err)
	}

	if got := refsOf(bob.runtime); got != 1 {
		t.Fatalf("bob's refs = %d after alice's double Close, want 1", got)
	}
	if !inRegistry(bob.runtime.path) {
		t.Fatal("alice's double Close tore down the runtime bob still held")
	}
	select {
	case <-bob.runtime.closed:
		t.Fatal("bob's runtime was shut down while bob still held it")
	default:
	}
}

func TestStatusOfAfterCloseReturnsRatherThanHangs(t *testing.T) {
	cfg := embeddedConfig(t)
	handle, err := Open(cfg, "alice")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A call on a torn-down runtime must RETURN, not wedge: the worker pool is gone, and the queued
	// read answers on the shutdown signal. Step 4 turns this into LJ_BAD_HANDLE at the cgo layer; here
	// it must at least not hang a thread, which is worse than a crash.
	done := make(chan error, 1)
	go func() {
		_, err := handle.StatusOf("work/site")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("StatusOf after Close returned no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("StatusOf after Close hung instead of returning")
	}
}

func TestCloseReturnsABlockedPollAtOnce(t *testing.T) {
	cfg := embeddedConfig(t)
	handle, err := Open(cfg, "alice")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const timeout = 10 * time.Second
	returned := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		handle.PollMutations(0, timeout) // an empty ring blocks until timeout or Close
		returned <- time.Since(start)
	}()

	// Give the poll time to reach its blocking select before closing.
	time.Sleep(50 * time.Millisecond)

	closeStart := time.Now()
	if err := handle.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if closeDur := time.Since(closeStart); closeDur > time.Second {
		t.Fatalf("Close took %v while a poll was blocked, want milliseconds", closeDur)
	}

	select {
	case elapsed := <-returned:
		if elapsed >= timeout {
			t.Fatalf("poll blocked the full %v; Close did not interrupt it", timeout)
		}
		if elapsed > time.Second {
			t.Fatalf("poll returned after %v, want milliseconds", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("poll did not return within 2s of Close")
	}
}

// refsOf reads a runtime's refcount under the registry lock, the way the package does.
func refsOf(rt *Runtime) int {
	registryMu.Lock()
	defer registryMu.Unlock()
	return rt.refs
}

// inRegistry reports whether a path still has a live runtime.
func inRegistry(path string) bool {
	registryMu.Lock()
	defer registryMu.Unlock()
	_, ok := registry[path]
	return ok
}
