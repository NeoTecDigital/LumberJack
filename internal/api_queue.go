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
func (server *Server) queuedNodeView(path string) (nodeView, error) {
	responseChan := make(chan APIResponse, 1)

	request := APIRequest{
		Type: "GET_NODE",
		Path: path,
		Callback: func(forest *core.Node) interface{} {
			var result interface{}
			server.readForest(func() {
				node, err := server.getNodeFromPath(path)
				if err != nil {
					result = err
					return
				}
				result = newNodeView(node)
			})
			return result
		},
		Response: responseChan,
	}

	server.apiQueue.queue <- request
	response := <-responseChan

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
}
