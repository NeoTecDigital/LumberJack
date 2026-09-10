// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// Benchmarks defending the three performance defects this codebase has already fixed.
//
// Each was a real outage shape, and each is guarded today by ONE assertion — a bytes-per-node budget
// for the marshal, a document-size budget for the projection, a wall-clock margin for the fsync.
// Those say "not catastrophic". They do not say how the cost GROWS, which is the only thing that
// tells an exponential apart from a linear one before it is in production: a regression that made
// the marshal quadratic would sit comfortably inside a per-node byte budget at twelve rungs and take
// the process down at twenty.
//
// So each benchmark is run at two sizes on the same shape. Comparing them is what reads the growth
// rate off the numbers:
//
//	go test ./internal -run '^$' -bench 'Ladder|Forest|Flush' -benchmem
//
// A doubling of the shape that better than doubles the cost is the regression. They are benchmarks
// and not assertions on purpose — a wall-clock threshold on a shared build box is a flake — but
// b/op on the two marshal and projection benchmarks is deterministic and is the number to watch.
package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

// benchServer builds a stock install in a temp directory and returns it with its admin.
func benchServer(b *testing.B) (*Server, string) {
	b.Helper()
	dir := b.TempDir()
	config := coreConfig()
	config.Process.ID = "bench_process"
	config.Process.DatabasePath = dir
	config.Process.Name = "bench"

	server := newServerCore(config)
	if _, err := server.EnsureSystemUser(); err != nil {
		b.Fatalf("EnsureSystemUser: %v", err)
	}
	b.Cleanup(func() { server.Shutdown(context.Background()) })
	return server, SystemUserID
}

// benchLadder builds a chain of diamonds: the shape that made both the marshal and the projection
// exponential, because the number of PATHS to the bottom rung doubles with every rung while the
// number of NODES grows by three.
//
// It is the same construction TestPersistIsBoundedByTheSizeOfTheForest and
// TestForestProjectionEmitsADiamondOnceNotOncePerPath use, built through the embedded surface so a
// benchmark does not depend on the HTTP test helpers.
func benchLadder(b *testing.B, server *Server, userID string, rungs int) {
	b.Helper()
	branch := func(path string) {
		if _, err := server.CreateNode(userID, CreateNodeRequest{Path: path, Type: "branch"}); err != nil {
			b.Fatalf("create branch %s: %v", path, err)
		}
	}

	path := "work"
	branch(path)
	for rung := 1; rung <= rungs; rung++ {
		left := fmt.Sprintf("%s/left-%d", path, rung)
		right := fmt.Sprintf("%s/right-%d", path, rung)
		bottom := fmt.Sprintf("%s/rung-%d", left, rung)
		branch(left)
		branch(right)
		branch(bottom)

		// The edge that closes the diamond, made the way handleLinkNode makes it — under the
		// exclusive hold, both directions recorded.
		if err := server.changeForest(func() error {
			parent, err := server.getNodeFromPath(right)
			if err != nil {
				return err
			}
			child, err := server.getNodeFromPath(bottom)
			if err != nil {
				return err
			}
			parent.Children[child.ID] = child
			child.AddParent(parent)
			return nil
		}); err != nil {
			b.Fatalf("link rung %d: %v", rung, err)
		}
		path = bottom
	}
}

// THE EXPONENTIAL MARSHAL. persistState serialized the forest as a TREE, so a node reachable by k
// paths was written k times; a ladder of diamonds makes k exponential in the node count. Twelve
// rungs was 38 nodes and 9.2 MB, sixteen was 50 nodes and 149 MB — built in memory, under the
// exclusive forest hold, on every mutation.
//
// b/op is the number. Four more rungs adds twelve nodes; on the flat node table that is a few
// kilobytes, and on a tree it is sixteen times the document.
func BenchmarkEncodeStateOverALadderOfDiamonds(b *testing.B) {
	for _, rungs := range []int{12, 16} {
		b.Run(fmt.Sprintf("rungs=%d", rungs), func(b *testing.B) {
			server, userID := benchServer(b)
			benchLadder(b, server, userID, rungs)
			nodes := countNodes(server.forest)

			b.ReportMetric(float64(nodes), "nodes")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				payload, err := encodeState(server.forest)
				if err != nil {
					b.Fatalf("encodeState: %v", err)
				}
				b.SetBytes(int64(len(payload)))
			}
		})
	}
}

// THE EXPONENTIAL PROJECTION. newNodeView carried an ON-PATH set, so cycles terminated but a
// doubly-reachable node was re-projected on every path through it — the same ladder, the same
// blow-up, this time under the forest READ hold with every writer stalled behind it.
//
// The fix emits a body once and a reference thereafter, which makes the cost a function of EDGES.
// Doubling the rungs must roughly double the work, not square it.
func BenchmarkForestProjectionOverALadderOfDiamonds(b *testing.B) {
	for _, rungs := range []int{12, 16} {
		b.Run(fmt.Sprintf("rungs=%d", rungs), func(b *testing.B) {
			server, userID := benchServer(b)
			benchLadder(b, server, userID, rungs)

			b.ReportMetric(float64(countNodes(server.forest)), "nodes")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				view := newNodeView(server.forest, userID)
				if view.ID == "" {
					b.Fatal("the projection produced nothing")
				}
			}
		})
	}
}

// The projection over a WIDE forest rather than a deep one, which is the shape a real install has.
// It is here so a change that fixed the diamond case by making the ordinary case worse — memoising
// everything, say — shows up as a regression somewhere.
func BenchmarkForestProjectionOverAWideForest(b *testing.B) {
	for _, leaves := range []int{200, 400} {
		b.Run(fmt.Sprintf("leaves=%d", leaves), func(b *testing.B) {
			server, userID := benchServer(b)
			for i := 0; i < leaves; i++ {
				if _, err := server.CreateNode(userID, CreateNodeRequest{
					Path: fmt.Sprintf("work/leaf-%d", i), Type: "leaf",
				}); err != nil {
					b.Fatalf("create leaf %d: %v", i, err)
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				newNodeView(server.forest, userID)
			}
		})
	}
}

// THE FSYNC STALL. Every mutating route used to flush the state file INSIDE the exclusive forest
// hold, so an fsync that took nineteen seconds under host congestion held off every other request —
// reads included — for nineteen seconds. /health answered in 25ms the whole time, because it takes
// no lock, so the relay in front reported the datastore as unreachable while it was merely stalled.
//
// What this measures is the READ's latency while a flush is in flight. With the disk inside the hold
// it is the whole flush; with the disk outside it is microseconds. The flush is made slow
// deliberately — a real fsync on a fast disk is too quick to tell the two apart.
func BenchmarkReadLatencyDuringASlowFlush(b *testing.B) {
	server, userID := benchServer(b)
	if _, err := server.CreateNode(userID, CreateNodeRequest{Path: "work/flush", Type: "leaf"}); err != nil {
		b.Fatalf("seed: %v", err)
	}

	// A flush that takes a fixed, visible time, standing in for a congested disk.
	const flushCost = 20 * time.Millisecond
	realWrite := server.stateWriter.write
	server.stateWriter.write = func(snapshot stateSnapshot) error {
		time.Sleep(flushCost)
		return realWrite(snapshot)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var writing sync.WaitGroup
		writing.Add(1)
		go func(n int) {
			defer writing.Done()
			server.CreateNode(userID, CreateNodeRequest{
				Path: fmt.Sprintf("work/w%d", n), Type: "leaf",
			})
		}(i)

		// Let the write reach the disk before the read is timed, so the read is measured against a
		// flush that is genuinely in flight.
		time.Sleep(flushCost / 4)
		started := time.Now()
		server.Forest(userID)
		b.ReportMetric(float64(time.Since(started).Microseconds()), "µs/read")

		writing.Wait()
	}
}

// The whole acknowledged write, end to end, under the same slow flush — the other half of the
// trade. Taking the disk out of the hold must not have made a single write slower than the flush it
// waits on, and coalescing means a queue of writers costs two flushes rather than one flush each.
func BenchmarkConcurrentAcknowledgedWritesUnderASlowFlush(b *testing.B) {
	server, userID := benchServer(b)

	const flushCost = 20 * time.Millisecond
	realWrite := server.stateWriter.write
	var flushes int64
	var flushMu sync.Mutex
	server.stateWriter.write = func(snapshot stateSnapshot) error {
		flushMu.Lock()
		flushes++
		flushMu.Unlock()
		time.Sleep(flushCost)
		return realWrite(snapshot)
	}

	const writers = 16
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var group sync.WaitGroup
		for w := 0; w < writers; w++ {
			group.Add(1)
			go func(n int) {
				defer group.Done()
				if _, err := server.CreateNode(userID, CreateNodeRequest{
					Path: fmt.Sprintf("work/r%d-w%d", i, n), Type: "leaf",
				}); err != nil {
					b.Errorf("write: %v", err)
				}
			}(w)
		}
		group.Wait()
	}
	b.StopTimer()

	flushMu.Lock()
	// Flushes per round. Coalescing is what keeps this near two rather than near `writers`.
	b.ReportMetric(float64(flushes)/float64(b.N), "flushes/round")
	flushMu.Unlock()
}

// The worker pool's read path, which is the one place a request can be refused for being late rather
// than for being wrong. It is here so the admission cost of a HEALTHY queue is on the record: the
// 429 the saturated case answers is only acceptable while the ordinary case is far from it.
func BenchmarkQueuedNodeViewOnAHealthyPool(b *testing.B) {
	server, userID := benchServer(b)
	for i := 0; i < 50; i++ {
		if _, err := server.CreateNode(userID, CreateNodeRequest{
			Path: fmt.Sprintf("work/leaf-%d", i), Type: "leaf",
		}); err != nil {
			b.Fatalf("seed %d: %v", i, err)
		}
	}
	if err := server.updateCache(); err != nil {
		b.Fatalf("updateCache: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := server.queuedNodeView("work/leaf-0", userID); err != nil {
				var carried *apiError
				if asAPIError(err, &carried) && carried.Status() == http.StatusTooManyRequests {
					b.Error("a healthy pool answered 429; the admission window is being reached " +
						"under ordinary load")
					return
				}
				b.Errorf("queuedNodeView: %v", err)
				return
			}
		}
	})
}

// The growth rate, as an ASSERTION rather than a number to read off a benchmark.
//
// The benchmarks above measure; they cannot go red. This is the part that can. Both defects had the
// same signature — cost proportional to the number of PATHS through the graph rather than to the
// number of NODES in it — and on a ladder of diamonds those two diverge violently: four more rungs
// adds twelve nodes and SIXTEEN TIMES the paths.
//
// So the assertion is a ratio, and it is measured in BYTES, which are deterministic. Wall clock on a
// shared build box is not, which is why there is no timing assertion here.
func TestMarshalAndProjectionGrowWithNodesNotPaths(t *testing.T) {
	measure := func(t *testing.T, rungs int) (nodes, stateBytes, viewBytes int) {
		t.Helper()
		server, _ := newStockServer(t)
		defer server.Shutdown(context.Background())
		userID := adminID(t, server)
		ladder(t, server, userID, rungs)

		payload, err := encodeState(server.forest)
		if err != nil {
			t.Fatalf("%d rungs: encodeState: %v", rungs, err)
		}
		view, err := json.Marshal(newNodeView(server.forest, userID))
		if err != nil {
			t.Fatalf("%d rungs: marshal the projection: %v", rungs, err)
		}
		return countNodes(server.forest), len(payload), len(view)
	}

	const small, large = 12, 16
	smallNodes, smallState, smallView := measure(t, small)
	largeNodes, largeState, largeView := measure(t, large)

	if largeNodes <= smallNodes {
		t.Fatalf("%d rungs is %d nodes and %d rungs is %d: the ladder is not growing",
			small, smallNodes, large, largeNodes)
	}

	// The four extra rungs multiply the PATHS by sixteen and the NODES by about 1.3. A cost that
	// tracks nodes stays near the node ratio; a cost that tracks paths runs away. The budget is the
	// node ratio doubled, which is far above any honest constant factor and far below 16x.
	nodeRatio := float64(largeNodes) / float64(smallNodes)
	budget := nodeRatio * 2

	if got := float64(largeState) / float64(smallState); got > budget {
		t.Errorf("the state document grew %.2fx for a %.2fx growth in nodes (%d -> %d bytes): the "+
			"marshal is tracking paths, not nodes", got, nodeRatio, smallState, largeState)
	}
	if got := float64(largeView) / float64(smallView); got > budget {
		t.Errorf("the projection grew %.2fx for a %.2fx growth in nodes (%d -> %d bytes): the "+
			"projection is tracking paths, not nodes", got, nodeRatio, smallView, largeView)
	}

	t.Logf("%d rungs: %d nodes, %d state bytes, %d view bytes", small, smallNodes, smallState, smallView)
	t.Logf("%d rungs: %d nodes, %d state bytes, %d view bytes", large, largeNodes, largeState, largeView)
}
