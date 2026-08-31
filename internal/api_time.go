package internal

import (
	"encoding/json"
	"net/http"
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

	// getNodeFromPath, not GetNode: the field is a PATH, and GetNode matches a node id. Node ids
	// are generated, so no client can name one — these routes could only ever 404.
	node, err := server.getNodeFromPath(request.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if _, err := node.StartTimeTracking(userID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Write changes to file
	if err := server.writeChangesToFile(server.statePath()); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

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

	node, err := server.getNodeFromPath(request.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if _, err := node.StopTimeTracking(userID); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Saved BEFORE the body is written: writing a body commits a 200, and a failure to persist
	// after that is a success the caller cannot tell from a real one.
	if err := server.writeChangesToFile(server.statePath()); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	summary := node.GetTimeTrackingSummary(userID)
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

	node, err := server.getNodeFromPath(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	summary := node.GetTimeTrackingSummary(userID)
	if summary == nil {
		summary = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}
