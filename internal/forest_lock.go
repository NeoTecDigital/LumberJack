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
// AND THE DISK IS OUTSIDE IT. The mutation and the marshal are inside the exclusive hold; the
// write and the fsyncs that publish the marshalled bytes are not. See state_writer.go: an fsync
// under this lock stalled every other request behind it, reads included, for as long as the disk
// took.
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

// changeForest runs change with the forest held EXCLUSIVELY, serializes the result under the same
// hold, and makes it durable OUTSIDE it before answering.
//
// THE MARSHAL IS STILL INSIDE THE HOLD. That is the guarantee c95ef33 exists for and it has not
// moved: a serialization of the forest and a mutation of the forest still cannot overlap, so the
// snapshot the writer takes away is a whole consistent state, and nothing it touches is shared with
// a concurrent request.
//
// THE DISK IS NOT. Flushing inside the hold made every request — reads included — queue behind an
// fsync, which under host congestion ran to nineteen seconds and read to the relay in front as an
// unreachable datastore. The write and its two fsyncs now happen with the forest free.
//
// The acknowledgment is unchanged in strength: this still does not return until the snapshot
// containing the change is on the disk. See state_writer.go for how concurrent snapshots are kept
// in order and coalesced.
func (server *Server) changeForest(change func() error) error {
	snapshot, err := server.applyChangeLocked(change)
	if err != nil {
		return err
	}

	if err := server.commitState(snapshot); err != nil {
		server.logger.Failure("Failed to save state: %v", err)
		return apiErrorf(http.StatusInternalServerError, "Failed to save state")
	}
	return nil
}

// applyChangeLocked makes the change and serializes the forest it produced, both under one
// exclusive hold, and answers the snapshot the caller must make durable.
//
// The hold ends when this returns. Nothing below it may touch the disk.
func (server *Server) applyChangeLocked(change func() error) (stateSnapshot, error) {
	server.forestMutex.Lock()
	defer server.forestMutex.Unlock()

	if err := change(); err != nil {
		return stateSnapshot{}, err
	}

	snapshot, err := server.encodeStateLocked(server.statePath())
	if err != nil {
		server.logger.Failure("Failed to save state: %v", err)
		return stateSnapshot{}, apiErrorf(http.StatusInternalServerError, "Failed to save state")
	}
	return snapshot, nil
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

// asAPIError reports whether an error carries a status, and hands it back if so. It exists so tests
// and callers can ask about the status without importing errors at every use.
func asAPIError(err error, target **apiError) bool {
	return errors.As(err, target)
}
