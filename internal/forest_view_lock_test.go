// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "testing"

func TestForestViewLockWriteEntryAndExitAdvanceGeneration(t *testing.T) {
	var mutex forestViewRWMutex
	mutex.RLock()
	before, reusable := mutex.snapshotGeneration()
	mutex.RUnlock()
	if before != 0 || !reusable {
		t.Fatal("zero-value forest reader generation is not reusable")
	}
	mutex.Lock()
	active, reusable := mutex.snapshotGeneration()
	mutex.Unlock()
	mutex.RLock()
	after, ready := mutex.snapshotGeneration()
	mutex.RUnlock()
	if active != 1 || reusable || after != 2 || !ready {
		t.Fatal("exclusive entry/exit did not invalidate structural reuse", active, after)
	}
}

func TestForestViewLockTryMethodsAndReadLockerPreserveRWMutexBehavior(t *testing.T) {
	var mutex forestViewRWMutex
	reader := mutex.RLocker()
	reader.Lock()
	if mutex.TryLock() {
		t.Fatal("exclusive try-lock passed a held reader")
	}
	if !mutex.TryRLock() {
		t.Fatal("shared try-lock refused another reader")
	}
	mutex.RUnlock()
	reader.Unlock()
	if mutex.generation.Load() != 0 || !mutex.TryLock() {
		t.Fatal("readers/failed try-lock changed generation or exclusive availability")
	}
	if mutex.TryRLock() || mutex.TryLock() {
		t.Fatal("try-lock passed an existing writer")
	}
	if current, reusable := mutex.snapshotGeneration(); current != 1 || reusable {
		t.Fatal("successful exclusive try-lock did not invalidate reuse")
	}
	mutex.Unlock()
	if mutex.generation.Load() != 2 {
		t.Fatal("exclusive try-lock release did not invalidate reuse")
	}
}

func TestForestViewLockOverflowPermanentlyDisablesSnapshotReuse(t *testing.T) {
	var mutex forestViewRWMutex
	mutex.generation.Store(^uint64(0) - 1)
	mutex.Lock()
	if current, reusable := mutex.snapshotGeneration(); current != ^uint64(0) || reusable {
		t.Fatal("last writer generation became reusable")
	}
	mutex.Unlock()
	mutex.RLock()
	current, reusable := mutex.snapshotGeneration()
	mutex.RUnlock()
	if current != ^uint64(0) || reusable || !mutex.exhausted.Load() {
		t.Fatal("overflow wrapped or enabled structural reuse")
	}
	mutex.Lock()
	mutex.Unlock()
	mutex.RLock()
	_, reusable = mutex.snapshotGeneration()
	mutex.RUnlock()
	if reusable || mutex.generation.Load() != ^uint64(0) {
		t.Fatal("later writes revived an exhausted generation counter")
	}
}
