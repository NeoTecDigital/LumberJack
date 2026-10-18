// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestDomainSnapshotCacheReaderWriterGenerationRace(t *testing.T) {
	var mutex forestViewRWMutex
	var cache domainSnapshotCache
	var builds atomic.Int32
	var workers sync.WaitGroup
	errors := make(chan error, 16)
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go snapshotGenerationReader(&mutex, &cache, &builds, &workers, errors)
	}
	for i := 0; i < 20; i++ {
		mutex.Lock()
		mutex.Unlock()
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if mutex.generation.Load() != 40 || builds.Load() == 0 {
		t.Fatal("writer invalidation or concurrent read building was lost")
	}
}

func snapshotGenerationReader(mutex *forestViewRWMutex, cache *domainSnapshotCache, builds *atomic.Int32, workers *sync.WaitGroup, errors chan<- error) {
	defer workers.Done()
	for i := 0; i < 20; i++ {
		if err := snapshotGenerationOnce(mutex, cache, builds); err != nil {
			errors <- err
			return
		}
	}
	errors <- nil
}

func snapshotGenerationOnce(mutex *forestViewRWMutex, cache *domainSnapshotCache, builds *atomic.Int32) error {
	mutex.RLock()
	defer mutex.RUnlock()
	generation, reusable := mutex.snapshotGeneration()
	if !reusable || generation&1 != 0 {
		return fmt.Errorf("reader observed a reusable active-writer generation")
	}
	snapshot, err := snapshotTestHeld(mutex, cache, domainSnapshotKey{}, builds)
	if err == nil && snapshot.revision != fmt.Sprint(generation) {
		return fmt.Errorf("reader received a snapshot from another lock generation")
	}
	return err
}
