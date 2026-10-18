// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func snapshotTestRead(mutex *forestViewRWMutex, cache *domainSnapshotCache, key domainSnapshotKey, builds *atomic.Int32) (domainScopeSnapshot, error) {
	mutex.RLock()
	defer mutex.RUnlock()
	return snapshotTestHeld(mutex, cache, key, builds)
}

func snapshotTestHeld(mutex *forestViewRWMutex, cache *domainSnapshotCache, key domainSnapshotKey, builds *atomic.Int32) (domainScopeSnapshot, error) {
	generation, reusable := mutex.snapshotGeneration()
	return cache.snapshot(generation, reusable, key, func() (domainScopeSnapshot, error) {
		builds.Add(1)
		return domainScopeSnapshot{revision: fmt.Sprint(generation)}, nil
	})
}

func TestDomainSnapshotCacheSharesOnlyOneReadGenerationAndInvalidatesBothWriteEdges(t *testing.T) {
	var mutex forestViewRWMutex
	var cache domainSnapshotCache
	var builds atomic.Int32
	key := domainSnapshotKey{binding: stagedTestBinding(), bounds: stagedTestBounds()}
	_, _ = snapshotTestRead(&mutex, &cache, key, &builds)
	_, _ = snapshotTestRead(&mutex, &cache, key, &builds)
	if builds.Load() != 1 {
		t.Fatal("same-generation read snapshots were rebuilt")
	}
	mutex.Lock()
	_, _ = snapshotTestHeld(&mutex, &cache, key, &builds)
	_, _ = snapshotTestHeld(&mutex, &cache, key, &builds)
	if builds.Load() != 3 || len(cache.entries) != 0 {
		t.Fatal("writer entry or repeated same-hold snapshot reused a prior build")
	}
	mutex.Unlock()
	_, _ = snapshotTestRead(&mutex, &cache, key, &builds)
	_, _ = snapshotTestRead(&mutex, &cache, key, &builds)
	if builds.Load() != 4 || len(cache.entries) != 1 || cache.generation != 2 {
		t.Fatal("write exit reused the writer snapshot or retained an old generation")
	}
}

func TestDomainSnapshotCacheKeysExactScopeBoundsAndDescriptor(t *testing.T) {
	var mutex forestViewRWMutex
	var cache domainSnapshotCache
	var builds atomic.Int32
	original := domainSnapshotKey{binding: stagedTestBinding(), bounds: stagedTestBounds()}
	otherScope, otherBounds, otherDescriptor := original, original, original
	otherScope.binding.ScopeID = "other-scope"
	otherBounds.bounds.MaxNodes--
	otherDescriptor.descriptor.Binding.BindingRevision = "other-descriptor"
	for _, key := range []domainSnapshotKey{original, otherScope, otherBounds, otherDescriptor, original} {
		if _, err := snapshotTestRead(&mutex, &cache, key, &builds); err != nil {
			t.Fatal(err)
		}
	}
	if builds.Load() != 4 || len(cache.entries) != 4 {
		t.Fatal("scope, bounds or descriptor snapshots were conflated")
	}
	mutex.Lock()
	mutex.Unlock()
	_, _ = snapshotTestRead(&mutex, &cache, original, &builds)
	if builds.Load() != 5 || len(cache.entries) != 1 {
		t.Fatal("prior-generation cache keys were retained")
	}
}

func TestDomainSnapshotCacheConcurrentReadersShareOneBuild(t *testing.T) {
	var mutex forestViewRWMutex
	var cache domainSnapshotCache
	var builds atomic.Int32
	var readers sync.WaitGroup
	errors := make(chan error, 32)
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		readers.Add(1)
		go snapshotTestConcurrentReader(&mutex, &cache, &builds, &readers, start, errors)
	}
	close(start)
	readers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if builds.Load() != 1 {
		t.Fatal("concurrent readers rebuilt the same structural snapshot", builds.Load())
	}
}

func snapshotTestConcurrentReader(mutex *forestViewRWMutex, cache *domainSnapshotCache, builds *atomic.Int32, readers *sync.WaitGroup, start <-chan struct{}, errors chan<- error) {
	defer readers.Done()
	<-start
	_, err := snapshotTestRead(mutex, cache, domainSnapshotKey{}, builds)
	errors <- err
}

func TestDomainSnapshotCacheNeverRetainsBuilderErrorsOrOverflowSnapshots(t *testing.T) {
	var mutex forestViewRWMutex
	var cache domainSnapshotCache
	var builds atomic.Int32
	mutex.RLock()
	for i := 0; i < 2; i++ {
		_, err := cache.snapshot(0, true, domainSnapshotKey{}, func() (domainScopeSnapshot, error) {
			builds.Add(1)
			return domainScopeSnapshot{}, errStagedUnconfigured
		})
		if err != errStagedUnconfigured {
			t.Fatal("builder error was hidden")
		}
	}
	mutex.RUnlock()
	mutex.exhausted.Store(true)
	_, _ = snapshotTestRead(&mutex, &cache, domainSnapshotKey{}, &builds)
	_, _ = snapshotTestRead(&mutex, &cache, domainSnapshotKey{}, &builds)
	if builds.Load() != 4 || len(cache.entries) != 0 {
		t.Fatal("errors or overflow snapshots were reused")
	}
}
