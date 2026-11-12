// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
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
//
// THIS IS THE ONE WRITE PATH. Every mutation, in either persistence, holds a source-fence permit
// from BEFORE the forest is taken until its durable outcome is known, and runs under the hold
// through runChangeLocked, which brackets it with the staged-scope protection, the access-grant
// refresh and the hub's record of what changed. The permit's outcome is the persistence's: a change
// refused under the hold had no effect when the forest still has the revision it had before; one
// that could not be made durable is unknown to the fence; one that landed is finished.
func (server *Server) changeForest(change func() error) error {
	_, err := server.changeForestOp(engineWriteOp(), change)
	return err
}

// changeForestOp is the one write path, answering where the change became durable: the snapshot the
// state writer published (this one, or a newer one holding it), or the hot-log record in tiered mode.
//
// The permit is taken BEFORE the hold and settled AFTER the outcome is known, with neither the
// forest nor the writer held (docs/extension-api.md §4.1, §5): Refused when the change returned an
// error under the hold, Unknown when it could not be made durable, Durable when it landed.
func (server *Server) changeForestOp(op extension.WriteOp, change func() error) (extension.Commit, error) {
	permit, before, err := server.acquirePermit(op)
	if err != nil {
		return extension.Commit{}, err
	}
	land, err := server.stageChange(op, change)
	if err != nil {
		unchanged := permit.WantsRevision() && before != "" && before == server.forestRevision()
		permit.Settle(extension.Outcome{State: extension.WriteRefused, Unchanged: unchanged, Err: err})
		return extension.Commit{}, err
	}
	commit, err := land()
	if err != nil {
		permit.Settle(extension.Outcome{State: extension.WriteUnknown, Err: err})
		return extension.Commit{}, err
	}
	permit.Settle(extension.Outcome{State: extension.WriteDurable, Commit: commit})
	return commit, nil
}

// stageChange makes the change under the exclusive hold, in whichever persistence holds the
// forest, and answers what makes it durable with the hold released: the state file in snapshot
// mode, the change's log record in tiered mode.
func (server *Server) stageChange(op extension.WriteOp, change func() error) (func() (extension.Commit, error), error) {
	if server.tier != nil {
		seq, err := server.stageChangeLocked(op, change)
		if err != nil {
			return nil, err
		}
		return func() (extension.Commit, error) {
			return extension.Commit{Tiered: true, Seq: seq, Path: server.statePath()}, server.landTiered(seq)
		}, nil
	}
	snapshot, err := server.applyChangeLocked(op, change)
	if err != nil {
		return nil, err
	}
	return func() (extension.Commit, error) { return server.landSnapshot(snapshot) }, nil
}

// landSnapshot makes a snapshot durable, with no hold on the forest, and answers where it landed.
func (server *Server) landSnapshot(snapshot stateSnapshot) (extension.Commit, error) {
	stamp, err := server.stateWriter.commitStamped(snapshot)
	if err != nil {
		server.logger.Failure("Failed to save state: %v", err)
		return extension.Commit{}, apiErrorf(http.StatusInternalServerError, "Failed to save state")
	}
	server.logger.Debug("Saved changes to file: %s", snapshot.path)
	commit := extension.Commit{Seq: stamp.seq, Path: stamp.path}
	copy(commit.SHA256[:], stamp.hash)
	return commit, nil
}

// applyChangeLocked makes the change and serializes the forest it produced, both under one
// exclusive hold, and answers the snapshot the caller must make durable.
//
// The hold ends when this returns. Nothing below it may touch the disk.
func (server *Server) applyChangeLocked(op extension.WriteOp, change func() error) (stateSnapshot, error) {
	server.forestMutex.Lock()
	defer server.forestMutex.Unlock()

	if err := server.runChangeLocked(op, change); err != nil {
		return stateSnapshot{}, err
	}

	snapshot, err := server.encodeStateLocked(server.statePath())
	if err != nil {
		server.logger.Failure("Failed to save state: %v", err)
		return stateSnapshot{}, apiErrorf(http.StatusInternalServerError, "Failed to save state")
	}
	return snapshot, nil
}

// runChangeLocked runs a change and everything that brackets a change under the hold: the built-in
// owned-subtree guard is captured first and verified last, the write hooks bracket the change in
// registration order, the access grants are refreshed, and the hub is told what changed, from a
// before-image of the forest. The caller holds the forest exclusively. Both persistences come
// through here, so neither can make durable a change the guard or a hook refused.
func (server *Server) runChangeLocked(op extension.WriteOp, change func() error) error {
	guard, err := server.ownedGuard().captureLocked(op)
	if err != nil {
		return err
	}
	afters, err := server.beforeHooksLocked(op)
	if err != nil {
		guard.restoreLocked()
		return err
	}
	var before *correspondenceSnapshot
	if server.applicationHubEnabled.Load() {
		before = server.captureCorrespondence()
	}

	changeErr := change()
	if err := server.afterHooksLocked(afters, changeErr); err != nil {
		guard.restoreLocked()
		return err
	}
	if err := guard.verifyLocked(); err != nil {
		return apiErrorf(http.StatusForbidden, "%v", err)
	}
	if changeErr != nil {
		return changeErr
	}
	server.refreshAccessGrantsLocked()
	if before != nil {
		server.recordCompatibilityChanges(before)
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

// asAPIError reports whether an error carries a status, and hands it back if so. It exists so tests
// and callers can ask about the status without importing errors at every use.
func asAPIError(err error, target **apiError) bool {
	return errors.As(err, target)
}
