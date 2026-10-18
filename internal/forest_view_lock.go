// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"sync"
	"sync/atomic"
)

// forestViewRWMutex is the same forest lock, not a second serialization boundary.
// Each exclusive acquisition and release invalidates private structural snapshots.
// Like sync.RWMutex, it must not be copied after its first use.
type forestViewRWMutex struct {
	mutex      sync.RWMutex
	generation atomic.Uint64
	exhausted  atomic.Bool
}

func (m *forestViewRWMutex) Lock() {
	m.mutex.Lock()
	m.advanceGeneration()
}

func (m *forestViewRWMutex) Unlock() {
	// Advance before releasing: a following reader/writer must see the new stamp.
	m.advanceGeneration()
	m.mutex.Unlock()
}

func (m *forestViewRWMutex) RLock()   { m.mutex.RLock() }
func (m *forestViewRWMutex) RUnlock() { m.mutex.RUnlock() }

func (m *forestViewRWMutex) TryLock() bool {
	if !m.mutex.TryLock() {
		return false
	}
	m.advanceGeneration()
	return true
}

func (m *forestViewRWMutex) TryRLock() bool { return m.mutex.TryRLock() }

func (m *forestViewRWMutex) advanceGeneration() {
	current := m.generation.Load()
	if m.exhausted.Load() || current == ^uint64(0) {
		m.exhausted.Store(true)
		return
	}
	m.generation.Store(current + 1)
}

// Called ONLY while holding this forest lock. Odd means the caller is the
// writer; writers always rebuild, including repeated mutations in one hold.
func (m *forestViewRWMutex) snapshotGeneration() (uint64, bool) {
	current := m.generation.Load()
	return current, !m.exhausted.Load() && current&1 == 0
}

type forestViewReadLocker struct{ mutex *forestViewRWMutex }

func (m *forestViewRWMutex) RLocker() sync.Locker { return forestViewReadLocker{m} }
func (r forestViewReadLocker) Lock()              { r.mutex.RLock() }
func (r forestViewReadLocker) Unlock()            { r.mutex.RUnlock() }
