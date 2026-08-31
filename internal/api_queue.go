package internal

import (
	"fmt"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// The read cache over the forest, and the worker pool that reads through it.

func (server *Server) initCache() {
	server.cache = &Cache{
		Forest: core.NewForest("forest"),
	}
}

func (server *Server) getFromCache(path string) (*core.Node, error) {
	server.cache.mutex.RLock()
	defer server.cache.mutex.RUnlock()

	if server.cache.Forest == nil || !compareHashes(server.cache.LastHash, server.lastHash) {
		return nil, fmt.Errorf("cache miss")
	}

	if path == "" {
		return server.cache.Forest, nil
	}

	return server.cache.Forest.GetNode(path)
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

// queuedGetNode reads a node through the worker pool.
//
// The callback used to wrap its answer in a SECOND APIResponse, which the worker then stored in the
// Data field of the one it sends back. So Data was never a *core.Node and the unchecked assertion
// here panicked on every call — GET /forest/tree took the process down rather than answering.
func (server *Server) queuedGetNode(path string) (*core.Node, error) {
	responseChan := make(chan APIResponse, 1)

	request := APIRequest{
		Type: "GET_NODE",
		Path: path,
		Callback: func(forest *core.Node) interface{} {
			node, err := server.getNodeFromPath(path)
			if err != nil {
				return err
			}
			return node
		},
		Response: responseChan,
	}

	server.apiQueue.queue <- request
	response := <-responseChan

	if response.Error != nil {
		return nil, response.Error
	}

	switch result := response.Data.(type) {
	case error:
		return nil, result
	case *core.Node:
		return result, nil
	default:
		return nil, fmt.Errorf("unexpected response reading node %q", path)
	}
}
