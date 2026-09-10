package internal

import (
	"fmt"
	"net/http"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// errServerShuttingDown answers a queued read that raced the worker pool's teardown.
//
// The workers return on the shutdown signal WITHOUT draining the queue, so a request already handed
// to the pool would otherwise block forever on a response no worker is left to send. A caller — an
// embedded Close, a C caller on a stale handle — gets an error it can act on rather than a hung
// thread, which is the difference the FFI's "a call after close is not a crash" contract rests on.
var errServerShuttingDown = apiErrorf(http.StatusServiceUnavailable, "server is shutting down")

// errServerBusy answers a read the worker pool could not admit before apiQueueSendTimeout. It is a
// 429 by DELIBERATE choice, not necessity: a wire-neutral sentinel matched by errors.Is — the pattern
// ic_lj_open already uses for embedded.ErrLocked (embedded/lock.go), which carries no HTTP status at
// all — would tell it apart from errServerShuttingDown without any code. 429 is chosen instead so the
// FFI gets an unambiguous status through the code mapping it already has (LJ_BUSY), where a second 503
// would fold into errServerShuttingDown's LJ_CLOSED.
//
// The semantic cost, stated plainly: the queue is GLOBAL — one 100-deep channel and five workers for
// every client — so a 429 tells client B it sent too many requests when client A saturated the pool.
// RFC 7231 §6.6.4's 503 is the closer match for server-side overload; 429 is the accepted trade for a
// boundary status that reads as one thing. See statusForError and the Retry-After below.
var errServerBusy = apiErrorf(http.StatusTooManyRequests, "server is busy")

// retryAfterBusySeconds is the Retry-After a 429 carries, which RFC 6585 §4 says it SHOULD. The pool
// drains a queued read in the time one projection takes, so a one-second hint is honest and keeps a
// retrying client from spinning.
const retryAfterBusySeconds = "1"

// apiQueueSendTimeout bounds how long a read waits to be admitted to the worker pool when the queue
// is full. The pool drains a queued read in the time one projection takes, so a wait this long means
// it is genuinely saturated — and a bound of any length is what keeps a full queue from pinning the
// caller (an FFI thread with no other exit than a Close) forever.
const apiQueueSendTimeout = 5 * time.Second

// enqueue hands a request to the worker pool, bounded three ways: it proceeds the moment a worker
// slot is free, returns errServerShuttingDown if the pool is tearing down, and returns errServerBusy
// if neither happens within timeout. The timeout is a parameter so the bound itself is testable
// without a five-second wait.
func (server *Server) enqueue(request APIRequest, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case server.apiQueue.queue <- request:
		return nil
	case <-server.apiQueue.shutdown:
		return errServerShuttingDown
	case <-timer.C:
		return errServerBusy
	}
}

// The read cache over the forest, and the worker pool that reads through it.

func (server *Server) initCache() {
	server.cache = &Cache{
		Forest: core.NewForest("forest"),
	}
}

// getFromCache resolves path segments against the last forest that was persisted.
//
// BY NAME, which is what a path is. It used to hand the whole path string to core.GetNode, which
// searches by ID — so a real path never hit and cost a full DAG search before the walk that
// answered it, and the literal string "forest" resolved to the ROOT at any position, which is a
// second and contradictory rule for what a path means.
func (server *Server) getFromCache(segments []string) (*core.Node, error) {
	server.cache.mutex.RLock()
	defer server.cache.mutex.RUnlock()

	if server.cache.Forest == nil || !compareHashes(server.cache.LastHash, server.lastHash) {
		return nil, fmt.Errorf("cache miss")
	}

	if node, found := walkNames(server.cache.Forest, segments); found {
		return node, nil
	}
	return nil, fmt.Errorf("cache miss")
}

func (server *Server) updateCache() error {
	server.cache.mutex.Lock()
	defer server.cache.mutex.Unlock()

	server.cache.Forest = server.forest
	server.cache.LastHash = server.lastHash
	server.cache.LastUpdate = time.Now()
	return nil
}

func (server *Server) initAPIQueue(workers int) {
	server.apiQueue = &APIQueue{
		queue:    make(chan APIRequest, 100),
		workers:  workers,
		shutdown: make(chan struct{}),
	}

	// Start workers
	for i := 0; i < workers; i++ {
		server.apiQueue.wg.Add(1)
		go server.worker()
	}
}

func (server *Server) worker() {
	defer server.apiQueue.wg.Done()

	for {
		select {
		case req := <-server.apiQueue.queue:
			response := APIResponse{}
			response.Data = req.Callback(server.forest)
			req.Response <- response
		case <-server.apiQueue.shutdown:
			return
		}
	}
}

// queuedNodeView reads a node through the worker pool and PROJECTS it there.
//
// The callback used to wrap its answer in a SECOND APIResponse, which the worker then stored in the
// Data field of the one it sends back. So Data was never a *core.Node and the unchecked assertion
// here panicked on every call — GET /forest/tree took the process down rather than answering.
//
// What comes back is a VIEW, not a live node. Handing a *core.Node out of the read hold and
// projecting it in the handler afterwards would walk the maps of a node another request is free to
// be writing into, which is the whole defect forest_lock.go exists to close. The hold is taken here
// rather than in the handler because the handler's goroutine is not the one that does the reading.
//
// readNode rather than readForest: it is the one place the lookup, the READ PERMISSION CHECK and
// the projection all happen under the same hold, and this route had no permission check at all.
func (server *Server) queuedNodeView(path, userID string) (nodeView, error) {
	responseChan := make(chan APIResponse, 1)

	request := APIRequest{
		Type: "GET_NODE",
		Path: path,
		Callback: func(forest *core.Node) interface{} {
			var view nodeView
			if err := server.readNode(path, userID, core.ReadPermission, func(node *core.Node) error {
				view = newNodeView(node, userID)
				return nil
			}); err != nil {
				return err
			}
			return view
		},
		Response: responseChan,
	}

	// The hand-off is bounded three ways — a free slot, a teardown, or a timeout — so a FULL queue
	// can no longer block the caller forever. Without the timeout a read that arrives once the
	// workers have stopped, or one that arrives when 100 others are already queued, blocks
	// indefinitely; from the FFI that is a pinned OS thread whose only exit is a Close from another
	// thread. See enqueue and errServerBusy.
	if err := server.enqueue(request, apiQueueSendTimeout); err != nil {
		return nodeView{}, err
	}

	// If the response has already landed AND shutdown is closed, Go picks a ready case uniformly, so
	// a read that genuinely succeeded can report 503. That is acceptable: it happens only once
	// Shutdown has begun, and this is a READ — nothing was written, so nothing is lost by answering
	// "shutting down" to a caller whose runtime is going away regardless.
	select {
	case response := <-responseChan:
		if response.Error != nil {
			return nodeView{}, response.Error
		}
		switch result := response.Data.(type) {
		case error:
			return nodeView{}, result
		case nodeView:
			return result, nil
		default:
			return nodeView{}, fmt.Errorf("unexpected response reading node %q", path)
		}
	case <-server.apiQueue.shutdown:
		return nodeView{}, errServerShuttingDown
	}
}
