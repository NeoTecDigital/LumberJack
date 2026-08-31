package internal

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
)

// eventIDRequired is what a caller is told when it names no event. An event is stored UNDER its id,
// so a request without one silently created an event keyed on the empty string — which POST /events
// then reported back as an event with no name that no client could ever end or append to.
const eventIDRequired = "event_id is required"

// validEventID reports whether an id names something. Whitespace names nothing.
func validEventID(eventID string) bool {
	return strings.TrimSpace(eventID) != ""
}

// HTTP handler for assigning a user
func (server *Server) handleAssignUser(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("AssignUser")
	defer server.logger.Exit("AssignUser")

	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request struct {
		Path       string          `json:"path"`
		AssigneeID string          `json:"assignee_id"`
		Permission core.Permission `json:"permission"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, err := server.forest.GetNode(request.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Check if user has admin permission
	if !node.CheckPermission(userID, core.AdminPermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	assigneeUser := core.User{ID: request.AssigneeID}
	if err := node.AssignUser(assigneeUser, request.Permission); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Log activity
	node.AddActivity("assign_user", map[string]interface{}{
		"assignee_id": request.AssigneeID,
		"permission":  request.Permission,
	}, userID)

	// Write changes to file
	if err := server.writeChangesToFile(server.statePath()); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler for starting an event
func (server *Server) handleStartEvent(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request struct {
		Path     string                 `json:"path"`
		EventID  string                 `json:"event_id"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !validEventID(request.EventID) {
		http.Error(w, eventIDRequired, http.StatusBadRequest)
		return
	}

	node, err := server.getNodeFromPath(request.Path)
	if err != nil {
		http.Error(w, fmt.Sprintf("Path error: %v", err), http.StatusNotFound)
		return
	}

	// Checked HERE as well as inside StartEvent. core.StartEvent does close the hole, but it closes
	// it by returning an error, and every error out of it was reported as 500 — so a refusal was
	// indistinguishable from a server fault, and disagreed with /events/plan and /events/end.
	if !node.CheckPermission(userID, core.WritePermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	if err := node.StartEvent(request.EventID, userID, nil, nil, request.Metadata); err != nil {
		http.Error(w, fmt.Sprintf("Start event error: %v", err), http.StatusInternalServerError)
		return
	}

	// Save state after event creation
	if err := server.writeChangesToFile(server.statePath()); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler for ending an event
func (server *Server) handleEndEvent(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request struct {
		Path    string `json:"path"`
		EventID string `json:"event_id"`
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

	if !node.CheckPermission(userID, core.WritePermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	if err := node.EndEvent(request.EventID, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Persisted for the same reason a planned event is: an end that is never written is an event
	// that comes back ongoing on the next start.
	if err := server.writeChangesToFile(server.statePath()); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler for appending to an event
func (server *Server) handleAppendToEvent(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request struct {
		Path     string                 `json:"path"`
		EventID  string                 `json:"event_id"`
		Content  string                 `json:"content"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Failed to decode request: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("Looking for node at path: %s", request.Path)
	node, err := server.getNodeFromPath(request.Path)
	if err != nil {
		log.Printf("Failed to get node: %v", err)
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// The same explicit check, for the same reason: AppendToEvent refuses without write permission
	// and its refusal was answered as 500.
	if !node.CheckPermission(userID, core.WritePermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	log.Printf("Appending to event %s", request.EventID)
	entry := core.Entry{
		Content:   request.Content,
		Metadata:  request.Metadata,
		UserID:    userID,
		Timestamp: time.Now(),
		CreatedBy: userID,
		CreatedAt: time.Now(),
	}

	if err := node.AppendToEvent(request.EventID, userID, entry, request.Metadata); err != nil {
		log.Printf("Failed to append to event: %v", err)
		http.Error(w, fmt.Sprintf("Failed to append to event: %v", err), http.StatusInternalServerError)
		return
	}

	if err := server.writeChangesToFile(server.statePath()); err != nil {
		log.Printf("Failed to save state: %v", err)
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler for getting event entries
//
// It asked for NOTHING: no caller, no permission. core.GetEventEntries checks neither, so any valid
// session could read the entries of any event on any node in the forest regardless of what that
// session had been granted. Reading is a ReadPermission act and is now checked as one.
func (server *Server) handleGetEventEntries(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request struct {
		Path    string `json:"path"`
		EventID string `json:"event_id"`
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

	if !node.CheckPermission(userID, core.ReadPermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	entries, err := node.GetEventEntries(request.EventID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// HTTP handler for getting tree
func (server *Server) handleGetForest(w http.ResponseWriter, r *http.Request) {
	// PROJECTED, not encoded directly: a node carries its users and a user carries a bcrypt hash.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newNodeView(server.forest))
}

// HTTP handler for getting users
func (server *Server) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newUserViews(server.forest.Users))
}

func (server *Server) handlePlanEvent(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request struct {
		Path      string                 `json:"path"`
		EventID   string                 `json:"event_id"`
		StartTime string                 `json:"start_time"`
		EndTime   string                 `json:"end_time"`
		Metadata  map[string]interface{} `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !validEventID(request.EventID) {
		http.Error(w, eventIDRequired, http.StatusBadRequest)
		return
	}

	startTime, err := time.Parse(time.RFC3339, request.StartTime)
	if err != nil {
		http.Error(w, "Invalid start time format", http.StatusBadRequest)
		return
	}

	endTime, err := time.Parse(time.RFC3339, request.EndTime)
	if err != nil {
		http.Error(w, "Invalid end time format", http.StatusBadRequest)
		return
	}

	node, err := server.getNodeFromPath(request.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Checked HERE as well as inside PlanEvent, so that "you may not" answers 403 rather than the
	// 500 every refusal used to be reported as.
	if !node.CheckPermission(userID, core.WritePermission) {
		http.Error(w, "Insufficient permissions", http.StatusForbidden)
		return
	}

	if err := node.PlanEvent(request.EventID, userID, &startTime, &endTime, request.Metadata); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// PERSISTED. A planned event that is never written to the state file is gone on the next start,
	// which is the whole span of time a plan is for.
	if err := server.writeChangesToFile(server.statePath()); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler for getting a specific tree
func (server *Server) handleGetTree(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")

	node, err := server.queuedGetNode(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newNodeView(node))
}

// HTTP handler for getting server settings
func (server *Server) handleGetServerSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := server.requireAdmin(w, r); !ok {
		return
	}

	// Return safe subset of server settings
	settings := map[string]interface{}{
		"organization":  server.config.Organization,
		"server_port":   server.config.Process.ServerPort,
		"dashboard_url": server.config.Process.DashboardURL,
		"phone":         server.config.Phone,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

// HTTP handler for updating server settings
func (server *Server) handleUpdateServerSettings(w http.ResponseWriter, r *http.Request) {
	userID, ok := server.requireAdmin(w, r)
	if !ok {
		return
	}

	var settings types.ServerConfig
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Use the UpdateSettings helper instead of direct assignment
	if err := server.UpdateSettings(userID, settings); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update settings: %v", err), http.StatusInternalServerError)
		return
	}

	// Save state after settings update
	if err := server.writeChangesToFile(server.statePath()); err != nil {
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}
