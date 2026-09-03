package internal

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/vaziolabs/lumberjack/internal/core"
)

// DELETE /entries/{id} and DELETE /time/{id} — retracting a message, and removing a mistimed
// session.
//
// ADDRESSED BY ID AND NODE, the way DELETE /attachments/{id} is, and for the same reason: the id
// names the thing and the node says where to look, so a caller never has to have kept a note of
// which entry of which event of which map the engine put it in. What it must NOT be addressed by is
// the index, which is what an entry had instead of a name until now — an index is invalidated by
// every insertion and deletion before it, so a delete keyed on one deletes whatever has since slid
// into that position. That is the defect these routes could not have been written before.
//
// A TIME-TRACKING SENTINEL IS NOT DELETABLE AS AN ENTRY. A tracked span is two entries read as a
// pair, and the pairing is positional: the readers walk forward holding one open start per user and
// close it with the next stop. Remove the stop alone and the start it closed is re-paired with a
// LATER stop, silently lengthening a session nobody edited — a wrong number under a 200. So the
// span is the unit, DELETE /time/{id} removes both ends together, and DELETE /entries/{id} refuses
// a sentinel and says which route to use.

// handleDeleteEntry removes one entry from wherever on the node it is kept.
func (server *Server) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("DeleteEntry")
	defer server.logger.Exit("DeleteEntry")

	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	path := r.URL.Query().Get("path")
	entryID := mux.Vars(r)["id"]

	var at core.EntryLocation
	err := server.changeNode(path, userID, core.WritePermission, func(node *core.Node) error {
		located, err := node.DeleteEntry(entryID, userID)
		if err != nil {
			return asEntryError(err)
		}
		at = located
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	// The removal names the entry BY ID and reports the index it had. The index is history the
	// moment this returns — everything after it has moved up — which is exactly why the id is what
	// a client is expected to have been holding.
	announced := mutation(mutationEntryDeleted, path)
	announced.EntryID = entryID
	announced.EventID = at.EventID
	announced.EntryIndex = at.EntryIndex
	server.publish(announced)
	server.logger.Success("Deleted entry %s on %s for %s", entryID, path, userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id": entryID, "path": server.canonicalPath(path), "location": at,
	})
}

// handleDeleteTimeSpan removes a tracked span: the entry that opened it and the one that closed it.
//
// The id is the START's id, which is what GET /time and /query select=time both report as the
// span's `id`. A span is not stored — it is a pair read out of the node's entries — so it has no
// identity of its own, and the start's is the only name for it that survives an insertion.
func (server *Server) handleDeleteTimeSpan(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("DeleteTimeSpan")
	defer server.logger.Exit("DeleteTimeSpan")

	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	path := r.URL.Query().Get("path")
	spanID := mux.Vars(r)["id"]

	removed := 0
	err := server.changeNode(path, userID, core.WritePermission, func(node *core.Node) error {
		count, err := node.DeleteTimeSpan(spanID, userID)
		if err != nil {
			return asEntryError(err)
		}
		removed = count
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	announced := mutation(mutationTimeSpanDeleted, path)
	announced.EntryID = spanID
	server.publish(announced)
	server.logger.Success("Deleted time span %s on %s for %s", spanID, path, userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id": spanID, "path": server.canonicalPath(path), "entries_removed": removed,
	})
}

// asEntryError gives core's refusals the status a caller can act on.
//
// An id that is not there is a 404 rather than a 500, because a client told the server broke
// retries something that can never succeed. Half a span is a 409 and NAMES the route that can do
// what the caller meant — a refusal that does not say what to do instead is a dead end.
func asEntryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, core.ErrEntryNotFound):
		return apiErrorf(http.StatusNotFound, "%v", err)
	case errors.Is(err, core.ErrTimeSpanNotFound):
		return apiErrorf(http.StatusNotFound, "%v", err)
	case errors.Is(err, core.ErrEntryIsTimeSpanSentinel):
		return apiErrorf(http.StatusConflict,
			"%v: use DELETE /time/{id} to remove the whole span", err)
	default:
		return apiErrorf(http.StatusInternalServerError, "%v", err)
	}
}
