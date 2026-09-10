// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// Concurrency on the path the engine actually takes.
//
// The suite's concurrency coverage was real and ALL of it went through the HTTP handlers. The
// embedded API is what the C ABI serialises and what an in-process host calls, and nothing had ever
// driven it from more than one goroutine — so the forest lock, the state writer's ordering and the
// per-path refcount were each proven only under a request shape this layer does not use.
//
// The registry is package-global, so every test here opens a private temp directory: two tests
// sharing a path would share a runtime and the refcounts would be nonsense.
package embedded

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Concurrent writers through ONE handle. Every acknowledgement is a promise that the change is in
// the forest and on the disk, and the promise has to survive the other writers making it at the same
// moment — which is exactly what a per-node lock could not do (see internal/forest_lock.go).
func TestConcurrentWritersThroughOneHandle(t *testing.T) {
	cfg := embeddedConfig(t)
	handle, err := Open(cfg, "alice")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer handle.Close()

	const writers = 24
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)

	failures := make(chan error, writers)
	for i := 0; i < writers; i++ {
		done.Add(1)
		go func(n int) {
			defer done.Done()
			start.Wait() // release them together, so the writes genuinely overlap

			path := fmt.Sprintf("work/site-%d", n)
			if _, err := handle.CreateNode(CreateNodeRequest{Path: path, Type: "leaf"}); err != nil {
				failures <- fmt.Errorf("CreateNode %s: %w", path, err)
				return
			}
			if _, err := handle.StartEvent(StartEventRequest{Path: path, EventID: "shift"}); err != nil {
				failures <- fmt.Errorf("StartEvent %s: %w", path, err)
				return
			}
			if _, err := handle.AppendToEvent(AppendEventRequest{
				Path: path, EventID: "shift", Content: fmt.Sprintf("entry from %d", n),
			}); err != nil {
				failures <- fmt.Errorf("AppendToEvent %s: %w", path, err)
				return
			}
			if _, err := handle.EndEvent(EndEventRequest{Path: path, EventID: "shift"}); err != nil {
				failures <- fmt.Errorf("EndEvent %s: %w", path, err)
			}
		}(i)
	}

	start.Done()
	done.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("a concurrent write was refused: %v", err)
	}

	// EVERY acknowledged cycle is readable afterwards. A write that was acknowledged and then lost
	// out of the map another writer was growing is the defect this asserts against.
	for i := 0; i < writers; i++ {
		path := fmt.Sprintf("work/site-%d", i)
		entries, err := handle.EventEntries(EventEntriesRequest{Path: path, EventID: "shift"})
		if err != nil {
			t.Errorf("%s: the acknowledged event is gone: %v", path, err)
			continue
		}
		if len(entries) != 1 {
			t.Errorf("%s: %d entries survived, want 1", path, len(entries))
		}
	}
}

// Concurrent writers through DIFFERENT handles over one path. They share one runtime and one engine
// by construction, so this is the same forest reached through twenty-four front doors — which is
// what a host acting for many principals does, and what the refcount exists to make safe.
func TestConcurrentWritersThroughSeparateHandlesOnOnePath(t *testing.T) {
	cfg := embeddedConfig(t)

	const writers = 24
	handles := make([]*Handle, writers)
	for i := range handles {
		handle, err := Open(cfg, fmt.Sprintf("principal-%d", i))
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		handles[i] = handle
		defer handle.Close()
	}

	// One runtime, one engine, whatever the principal.
	for i := 1; i < writers; i++ {
		if handles[i].runtime != handles[0].runtime {
			t.Fatalf("handle %d did not share the first handle's runtime", i)
		}
	}

	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	failures := make(chan error, writers)

	for i, handle := range handles {
		done.Add(1)
		go func(n int, h *Handle) {
			defer done.Done()
			start.Wait()
			path := fmt.Sprintf("shared/leaf-%d", n)
			if _, err := h.CreateNode(CreateNodeRequest{Path: path, Type: "leaf"}); err != nil {
				failures <- fmt.Errorf("handle %d CreateNode: %w", n, err)
			}
		}(i, handle)
	}

	start.Done()
	done.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("a concurrent write through a separate handle was refused: %v", err)
	}

	// Read the result back through a handle that did not make any of them.
	forest := handles[0].Forest()
	shared, found := childNamed(forest, "shared")
	if !found {
		t.Fatal("the shared branch is not in the forest")
	}
	if got := len(shared.Children); got != writers {
		t.Fatalf("the shared branch holds %d leaves, want %d — writes through separate handles were lost",
			got, writers)
	}
}

// Concurrent READS beside concurrent writes. A projection walks the whole graph; a mutation writes
// into it. The read hold is what keeps the two apart, and the race detector is what proves it.
func TestConcurrentReadsBesideWritesThroughEmbedded(t *testing.T) {
	cfg := embeddedConfig(t)
	handle, err := Open(cfg, "alice")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer handle.Close()

	if _, err := handle.CreateNode(CreateNodeRequest{Path: "work/seed", Type: "leaf"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				handle.Forest()
				if _, err := handle.Query(QueryRequest{Select: "nodes"}); err != nil {
					return
				}
				if _, err := handle.Aggregate(AggregateRequest{Select: "nodes", Group: []string{"node_path"}}); err != nil {
					return
				}
			}
		}()
	}

	var writers sync.WaitGroup
	for i := 0; i < 8; i++ {
		writers.Add(1)
		go func(n int) {
			defer writers.Done()
			for j := 0; j < 8; j++ {
				if _, err := handle.CreateNode(CreateNodeRequest{
					Path: fmt.Sprintf("work/w%d-%d", n, j), Type: "leaf",
				}); err != nil {
					t.Errorf("write %d-%d: %v", n, j, err)
					return
				}
			}
		}(i)
	}

	writers.Wait()
	close(stop)
	readers.Wait()
}

// A poll running while mutations land sees a coherent, ordered feed — no duplicates, no reordering,
// and never a sequence it has already been given.
func TestPollingBesideConcurrentWritesStaysOrdered(t *testing.T) {
	cfg := embeddedConfig(t)
	handle, err := Open(cfg, "alice")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer handle.Close()

	const writes = 60
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < writes; i++ {
			if _, err := handle.CreateNode(CreateNodeRequest{
				Path: fmt.Sprintf("work/n%d", i), Type: "leaf",
			}); err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
		}
	}()

	var cursor uint64
	deadline := time.Now().Add(20 * time.Second)
	for cursor < writes && time.Now().Before(deadline) {
		batch := handle.PollMutations(cursor, 100*time.Millisecond)
		if !batch.CaughtUp {
			t.Fatalf("the poller fell off the ring after %d mutations; %d mutations cannot outrun a "+
				"%d-deep replay buffer", cursor, writes, 1024)
		}
		for _, event := range batch.Events {
			if event.Sequence <= cursor {
				t.Fatalf("poll returned sequence %d at cursor %d: the feed repeated or reordered",
					event.Sequence, cursor)
			}
			if event.Sequence != cursor+1 {
				t.Fatalf("poll jumped from %d to %d: a mutation went unannounced", cursor, event.Sequence)
			}
			cursor = event.Sequence
		}
	}

	<-done
	if cursor < writes {
		t.Fatalf("the poller saw %d mutations, want at least %d", cursor, writes)
	}
}

// childNamed finds a projected child by name. A NodeView's Children map is keyed by node ID, so a
// test that knows the name has to scan for it.
func childNamed(view NodeView, name string) (NodeView, bool) {
	for _, child := range view.Children {
		if child.Name == name {
			return child, true
		}
	}
	return NodeView{}, false
}
