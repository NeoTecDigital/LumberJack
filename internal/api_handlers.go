package internal

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
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

	err := server.changeNode(request.Path, userID, core.AdminPermission, func(node *core.Node) error {
		assignee := core.User{ID: request.AssigneeID}
		if err := node.AssignUser(assignee, request.Permission); err != nil {
			return apiErrorf(http.StatusBadRequest, "%v", err)
		}

		node.AddActivity("assign_user", map[string]interface{}{
			"assignee_id": request.AssigneeID,
			"permission":  request.Permission,
		}, userID)
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
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

	var request startEventRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := server.startEvent(userID, request); err != nil {
		writeAPIError(w, err)
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

	var request endEventRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := server.endEvent(userID, request); err != nil {
		writeAPIError(w, err)
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

	var request appendEventRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	announced, err := server.appendToEvent(userID, request)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	// The acknowledgement is read off the announced event: it carries the entry's id and index and
	// the canonical node path, which is exactly what this response says. See appendToEvent.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          announced.EntryID,
		"event_id":    announced.EventID,
		"entry_index": announced.EntryIndex,
		"node_path":   announced.NodePath,
	})
}

// HTTP handler for getting event entries
func (server *Server) handleGetEventEntries(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request eventEntriesRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	entries, err := server.eventEntries(userID, request)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// HTTP handler for getting tree
//
// FILTERED BY THE CALLER'S PERMISSIONS. It used to ask for no caller at all: POST /query filters
// every node it reports with CheckPermission, and this route — which returns the same forest, whole
// — answered all of it to any valid session. A user granted read on one branch was handed every
// other branch in the install.
func (server *Server) handleGetForest(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(server.forestView(userID))
}

// forestView projects the whole forest as the caller may see it, under the read hold.
//
// PROJECTED, not encoded directly: a node carries its users and a user carries a bcrypt hash. The
// projection is built under the READ hold; projecting walks every map in the graph, which is exactly
// the read that must not run beside a mutation, and the view it produces COPIES every map and slice
// it exposes, so anything encoding it afterwards is over a value nothing else can reach and a slow
// reader cannot hold up a writer. See forest_projection.go. It is a method, not the handler's body,
// because the embedded Forest() answers the same projection with no HTTP around it.
func (server *Server) forestView(userID string) nodeView {
	var view nodeView
	server.readForest(func() {
		view = newNodeView(server.forest, userID)
	})
	return view
}

// HTTP handler for getting users
//
// ADMINISTRATIVE. The list of every account in the install — their names, their emails and what
// each of them may reach — went to any valid session, which is the reconnaissance step before every
// other route is tried.
func (server *Server) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := server.requireAdmin(w, r); !ok {
		return
	}

	var views []userView
	server.readForest(func() {
		views = newUserViews(server.forest.Users)
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(views)
}

func (server *Server) handlePlanEvent(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request planEventRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := server.planEvent(userID, request); err != nil {
		writeAPIError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// plannedSpan reads what a plan needs: an event to be a plan FOR, and both of its ends. Both ends
// are required and both are RFC3339 — a plan with no span is not a plan.
func plannedSpan(eventID, start, end string) (time.Time, time.Time, error) {
	if !validEventID(eventID) {
		return time.Time{}, time.Time{}, apiErrorf(http.StatusBadRequest, eventIDRequired)
	}

	startTime, err := time.Parse(time.RFC3339, start)
	if err != nil {
		return time.Time{}, time.Time{}, apiErrorf(http.StatusBadRequest, "Invalid start time format")
	}

	endTime, err := time.Parse(time.RFC3339, end)
	if err != nil {
		return time.Time{}, time.Time{}, apiErrorf(http.StatusBadRequest, "Invalid end time format")
	}
	return startTime, endTime, nil
}

// HTTP handler for getting a specific tree
//
// FILTERED BY THE CALLER'S PERMISSIONS, like GET /forest and for the same reason: this route asked
// for no caller, so any valid session could name any path and be handed that subtree.
func (server *Server) handleGetTree(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	path := r.URL.Query().Get("path")

	// The projection is built inside the queue callback, which is where the forest is held for
	// reading. Handing a *core.Node back out of the hold and projecting it afterwards would be
	// projecting a node another request is free to be changing.
	view, err := server.queuedNodeView(path, userID)
	if err != nil {
		// writeAPIError, not a flat 404: a subtree the caller may not read is a 403, and telling it
		// apart from "there is no such node" is the difference between a refusal and a lie.
		writeAPIError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(view)
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

	// Use the UpdateSettings helper instead of direct assignment. It walks the root's user list,
	// so it runs inside the hold like every other change to the forest.
	err := server.changeForest(func() error {
		if err := server.UpdateSettings(userID, settings); err != nil {
			return apiErrorf(http.StatusInternalServerError, "Failed to update settings: %v", err)
		}
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}
