package internal

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/internal/graph"
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
	// retryAfter is the Retry-After this failure should carry, in seconds, or "" for none. It is on
	// the ERROR rather than inferred from the status because the two 429s this engine raises wait for
	// different lengths of time: a busy worker pool drains in about a second, and a second-factor
	// resend may be half a minute away. writeAPIError guessing "1" for both told one of them a
	// number that was simply wrong, which is worse than saying nothing.
	retryAfter string
}

func (e *apiError) Error() string { return e.message }

// apiErrorf builds a failure a client is answerable for.
func apiErrorf(status int, format string, args ...interface{}) *apiError {
	return &apiError{status: status, message: fmt.Sprintf(format, args...)}
}

// apiErrorRetryAfter builds one that also says how long to wait, which RFC 6585 §4 says a 429 SHOULD.
func apiErrorRetryAfter(status int, retryAfter, format string, args ...interface{}) *apiError {
	return &apiError{status: status, message: fmt.Sprintf(format, args...), retryAfter: retryAfter}
}

// writeAPIError answers a failure.
//
// An error carrying no status is a fault of the SERVER'S, and is answered 500 — a caller is not
// told it made a mistake in something it had no part in.
func writeAPIError(w http.ResponseWriter, err error) {
	var carried *apiError
	if errors.As(err, &carried) {
		// RFC 6585 §4: a 429 SHOULD say how long to wait. The header must be set BEFORE http.Error,
		// which calls WriteHeader and freezes the header block. The number comes from the ERROR and
		// not from the status: there is more than one 429 here now, and they do not wait the same
		// length of time.
		if carried.retryAfter != "" {
			w.Header().Set("Retry-After", carried.retryAfter)
		}
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
//
// A FAILED PERSIST IS NOT ROLLED BACK, DELIBERATELY. When commitState fails the caller gets a 500 and
// correctly does not believe the change is durable — but the change is still in the in-memory forest,
// because `change` already mutated the object graph and undoing an arbitrary mutation would mean
// snapshotting and restoring the whole forest on every write. That cost buys nothing a caller can
// observe: the next successful persist writes the WHOLE snapshot, change included, so memory and disk
// reconverge; and if the process instead dies during the failure window, the un-acknowledged change
// is lost, which is exactly what a 500 promised. Nothing acknowledged is ever lost — that is the
// contract, and TestChangeForestReportsAPersistThatCouldNotLand pins it. (The state writer clears its
// durable-hash on a failed flush, so the next persist WRITES rather than taking the unchanged skip.)
//
// IN TIERED MODE the same hold covers the mutation and the encoding of the CHANGE, and what
// becomes durable before the answer is the log record rather than a whole state file. See
// persistence.go.
func (server *Server) changeForest(change func() error) error {
	return server.commitChange(func() (*graph.Touched, error) { return nil, change() }, false)
}

// changeForestTracked is changeForest for a caller that can say which nodes it wrote — the graph
// engine. The change answers the touched set, which persistence logs instead of the forest, and
// the hub is told from it instead of from a walk of the whole forest.
func (server *Server) changeForestTracked(change func() (*graph.Touched, error)) error {
	return server.commitChange(change, true)
}

// commitChange routes a change to whichever persistence holds the forest.
func (server *Server) commitChange(change func() (*graph.Touched, error), tracked bool) error {
	if server.tier != nil {
		return server.commitTiered(change, tracked)
	}
	snapshot, err := server.applyChangeLocked(change, tracked)
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
func (server *Server) applyChangeLocked(change func() (*graph.Touched, error), tracked bool) (stateSnapshot, error) {
	server.forestMutex.Lock()
	defer server.forestMutex.Unlock()

	if _, err := server.runChangeLocked(change, tracked); err != nil {
		return stateSnapshot{}, err
	}

	snapshot, err := server.encodeStateLocked(server.statePath())
	if err != nil {
		server.logger.Failure("Failed to save state: %v", err)
		return stateSnapshot{}, apiErrorf(http.StatusInternalServerError, "Failed to save state")
	}
	return snapshot, nil
}

// runChangeLocked runs a change and everything that follows a change under the hold: the access
// grants are refreshed, and the hub is told what changed. The caller holds the forest exclusively.
//
// A TRACKED change says which nodes it wrote, so the hub is told from that set and the two walks
// of the whole forest that used to bracket every write do not run. An untracked change is
// bracketed as before. Whatever the grant refresh and the hub themselves wrote is added to the
// tracked set whole, so a persistence that logs the set logs those too.
func (server *Server) runChangeLocked(change func() (*graph.Touched, error), tracked bool) (*graph.Touched, error) {
	hub := server.applicationHubEnabled.Load()
	var before *correspondenceSnapshot
	if hub && !tracked {
		before = server.captureCorrespondence()
	}

	touched, err := change()
	if err != nil {
		return nil, err
	}
	if tracked && touched == nil {
		touched = graph.NewTouched()
	}
	for _, node := range server.refreshAccessGrantsLocked() {
		if touched != nil {
			touched.Rewrite(node)
		}
	}
	switch {
	case !hub:
	case touched != nil:
		if server.recordTrackedChanges(touched) {
			touched.Rewrite(server.forest)
		}
	default:
		server.recordCompatibilityChanges(before)
	}
	return touched, nil
}

// refuseGraphWrite is the ONE guard every generic write passes through: it refuses a target that
// is the `graph` root or anything beneath it, whoever asks and whatever they hold on it.
//
// THE DEFECT THIS EXISTS TO CLOSE: the graph is a subtree of the forest, so every route that
// writes a node by path could write the graph's. PATCH /nodes/graph/…/metadata rewrote an entity's
// kind — the one field the engine holds immutable — and DELETE /nodes/graph/_commands?mode=cascade
// removed every receipt, after which a retried command was applied a second time. Neither went
// through a command, so neither was validated, journaled, or given a revision.
//
// Only POST /graph/commands writes there. The target is named two ways and BOTH are checked: by
// PATH, which is all there is when the node does not exist yet, and by the NODE a path resolved
// to, so a graph node reached under some other name is refused as well. Pass a nil node when
// there is none to check. The caller holds the forest.
func (server *Server) refuseGraphWrite(path string, node *core.Node) error {
	segments := server.segmentsFrom(path)
	named := len(segments) > 0 && segments[0] == graph.RootName
	if !named && !graph.Owns(server.forest, node) {
		return nil
	}
	return apiErrorf(http.StatusForbidden,
		"%s belongs to the graph engine: it is changed only through POST /graph/commands", server.canonicalPath(path))
}

// writeTargetLocked resolves the node a generic write names, and is how every such write that
// starts from a path finds its node: the graph is refused before the lookup, so the answer is the
// same whether or not the node exists, and again on the node the lookup reached.
//
// what prefixes the 404 for a path that names nothing ("parent: "). The caller holds the forest.
func (server *Server) writeTargetLocked(path, what string) (*core.Node, error) {
	if err := server.refuseGraphWrite(path, nil); err != nil {
		return nil, err
	}
	node, err := server.getNodeFromPath(path)
	if err != nil {
		return nil, apiErrorf(http.StatusNotFound, "%s%v", what, err)
	}
	if err := server.refuseGraphWrite(path, node); err != nil {
		return nil, err
	}
	return node, nil
}

// changeNode is the shape every mutating route has: find the node a path names, confirm the caller
// may change it, change it, and persist — all under one exclusive hold.
//
// The lookup is INSIDE the hold. It walks the Children map of every node on the path, which is a
// read of the same maps a concurrent mutation writes. It goes through writeTargetLocked, so every
// route built on this shape — entries, events, time, metadata, attachments — is closed to the
// graph at once.
func (server *Server) changeNode(path, userID string, permission core.Permission, change func(*core.Node) error) error {
	return server.changeForest(func() error {
		node, err := server.writeTargetLocked(path, "")
		if err != nil {
			return err
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
