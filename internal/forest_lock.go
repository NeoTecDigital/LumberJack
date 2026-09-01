package internal

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// The one lock over the forest, and the shapes every route uses to take it.
//
// THE DEFECT THIS EXISTS TO CLOSE: POST /events/start answered 200 for an event that afterwards was
// in neither the state file nor memory.
//
// The forest is ONE object graph and persisting it serializes the WHOLE of it, but every mutator
// held only the mutex of the single node it was changing. Those are disjoint locks, so
// json.Marshal walked Children, Events, Users and Entries of every node while another request was
// writing into them. An unsynchronized Go map read against a concurrent write is not something the
// runtime promises to detect: when it does, the process dies; when it does not, the insert that was
// in flight can be dropped from the map that was being grown. The handler had already been told
// nil by StartEvent and nil by the persist, so it answered 200 for a write that no longer existed.
//
// The fix is not a smaller window. It is that a serialization of the forest and a mutation of the
// forest can never overlap: ONE reader-writer lock over the whole graph, held EXCLUSIVELY across
// both the mutation and the persist that acknowledges it, and held SHARED by everything that reads
// the graph — including the read routes, which serialize it just as thoroughly.
//
// ONLY THE HANDLERS TAKE IT. Anything below them (getNodeFromPath, the queue workers, core) must
// not, because Go's RWMutex queues a waiting writer ahead of later readers: a second RLock taken
// underneath a first one deadlocks the moment a writer is waiting between them.

// apiError is a failure together with the status it should be answered with.
//
// It lets a helper several calls below a handler say "there is no such node" or "you may not"
// without the handler having to infer either from the text of a message.
type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string { return e.message }

// apiErrorf builds a failure a client is answerable for.
func apiErrorf(status int, format string, args ...interface{}) *apiError {
	return &apiError{status: status, message: fmt.Sprintf(format, args...)}
}

// writeAPIError answers a failure.
//
// An error carrying no status is a fault of the SERVER'S, and is answered 500 — a caller is not
// told it made a mistake in something it had no part in.
func writeAPIError(w http.ResponseWriter, err error) {
	var carried *apiError
	if errors.As(err, &carried) {
		http.Error(w, carried.message, carried.status)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// readForest runs read with the forest held for reading, so nothing can change underneath it.
func (server *Server) readForest(read func()) {
	server.forestMutex.RLock()
	defer server.forestMutex.RUnlock()

	read()
}

// changeForest runs change with the forest held EXCLUSIVELY, and persists the result before it
// lets go.
//
// The persist is inside the same hold as the change on purpose. A persist outside it serializes a
// forest that another request may be halfway through changing, which is the defect this file
// exists to close; and an acknowledgment sent before the state file has the change in it is a
// success reported for something that did not happen.
func (server *Server) changeForest(change func() error) error {
	server.forestMutex.Lock()
	defer server.forestMutex.Unlock()

	if err := change(); err != nil {
		return err
	}

	if err := server.persistLocked(server.statePath()); err != nil {
		server.logger.Failure("Failed to save state: %v", err)
		return apiErrorf(http.StatusInternalServerError, "Failed to save state")
	}
	return nil
}

// changeNode is the shape every mutating route has: find the node a path names, confirm the caller
// may change it, change it, and persist — all under one exclusive hold.
//
// The lookup is INSIDE the hold. It walks the Children map of every node on the path, which is a
// read of the same maps a concurrent mutation writes.
func (server *Server) changeNode(path, userID string, permission core.Permission, change func(*core.Node) error) error {
	return server.changeForest(func() error {
		node, err := server.getNodeFromPath(path)
		if err != nil {
			return apiErrorf(http.StatusNotFound, "%v", err)
		}

		if !node.CheckPermission(userID, permission) {
			return apiErrorf(http.StatusForbidden, "Insufficient permissions")
		}

		return change(node)
	})
}

// readNode is the read counterpart of changeNode: find the node, confirm the caller may see it,
// read it — with the forest held for reading throughout.
//
// read must finish everything it needs from the node before returning. A node pointer that outlives
// the hold is a node another request is free to change.
func (server *Server) readNode(path, userID string, permission core.Permission, read func(*core.Node) error) error {
	server.forestMutex.RLock()
	defer server.forestMutex.RUnlock()

	node, err := server.getNodeFromPath(path)
	if err != nil {
		return apiErrorf(http.StatusNotFound, "%v", err)
	}

	if !node.CheckPermission(userID, permission) {
		return apiErrorf(http.StatusForbidden, "Insufficient permissions")
	}

	return read(node)
}
