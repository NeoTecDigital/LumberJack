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

	// Both the hand-off and the wait select on the shutdown signal. Without it a read that arrives
	// once the workers have stopped — a call racing Close, or one on a stale handle — enqueues into
	// the buffered channel and then blocks forever on a response that will never come. See
	// errServerShuttingDown.
	select {
	case server.apiQueue.queue <- request:
	case <-server.apiQueue.shutdown:
		return nodeView{}, errServerShuttingDown
	}

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
