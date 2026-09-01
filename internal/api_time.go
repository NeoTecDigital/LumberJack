package internal

import (
	"encoding/json"
	"net/http"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// The time-tracking routes: a span is opened, closed, and reported.

// HTTP handler for starting time tracking
func (server *Server) handleStartTimeTracking(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// changeNode resolves a PATH, not a node id: GetNode matches ids, ids are generated, and no
	// client can name one — these routes could only ever 404 when they used it.
	err := server.changeNode(request.Path, userID, core.WritePermission, func(node *core.Node) error {
		if _, err := node.StartTimeTracking(userID); err != nil {
			return apiErrorf(http.StatusForbidden, "%v", err)
		}
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	server.publish(mutation(mutationEntryAdded, request.Path))
	w.WriteHeader(http.StatusOK)
}

// HTTP handler for stopping time tracking
func (server *Server) handleStopTimeTracking(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request struct {
		Path string `json:"path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Saved BEFORE the body is written: writing a body commits a 200, and a failure to persist
	// after that is a success the caller cannot tell from a real one. The summary is read inside
	// the same hold, so it reports the span this call just closed and not one a later request
	// opened.
	var summary []map[string]interface{}
	err := server.changeNode(request.Path, userID, core.WritePermission, func(node *core.Node) error {
		if _, err := node.StopTimeTracking(userID); err != nil {
			return apiErrorf(http.StatusForbidden, "%v", err)
		}
		summary = node.GetTimeTrackingSummary(userID)
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	if summary == nil {
		summary = []map[string]interface{}{}
	}

	server.publish(mutation(mutationEntryAdded, request.Path))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

// HTTP handler for getting time tracking summary
func (server *Server) handleGetTimeTracking(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	// A QUERY PARAMETER, not a JSON body. This is a GET; no conforming client sends a body on one,
	// so decoding one made the route unreachable — every caller got 400 "EOF".
	path := r.URL.Query().Get("path")

	var summary []map[string]interface{}
	err := server.readNode(path, userID, core.ReadPermission, func(node *core.Node) error {
		summary = node.GetTimeTrackingSummary(userID)
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	if summary == nil {
		summary = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}
