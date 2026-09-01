package internal

import (
	"encoding/json"
	"errors"
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

	// The lookup, the permission check, the start and the persist are ONE exclusive hold on the
	// forest. Split apart, the persist serialized a graph other requests were writing into, and the
	// event this route had just acknowledged could be dropped out of the map it was inserted in.
	// See forest_lock.go.
	//
	// The permission is checked HERE as well as inside StartEvent. core.StartEvent does close the
	// hole, but it closes it by returning an error, and every error out of it was reported as 500 —
	// so a refusal was indistinguishable from a server fault, and disagreed with /events/plan and
	// /events/end.
	err := server.changeNode(request.Path, userID, core.WritePermission, func(node *core.Node) error {
		if err := node.StartEvent(request.EventID, userID, nil, nil, request.Metadata); err != nil {
			return apiErrorf(http.StatusInternalServerError, "Start event error: %v", err)
		}
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	announced := mutation(mutationEventStarted, request.Path)
	announced.EventID = request.EventID
	server.publish(announced)
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

	// Persisted inside the hold for the same reason a planned event is: an end that is never
	// written is an event that comes back ongoing on the next start.
	err := server.changeNode(request.Path, userID, core.WritePermission, func(node *core.Node) error {
		if err := node.EndEvent(request.EventID, userID); err != nil {
			return apiErrorf(http.StatusInternalServerError, "%v", err)
		}
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	announced := mutation(mutationEventEnded, request.Path)
	announced.EventID = request.EventID
	server.publish(announced)
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The same explicit check, for the same reason: AppendToEvent refuses without write permission
	// and its refusal was answered as 500.
	// The CONTENT is passed, not an Entry built around it. AppendToEvent's third argument IS the
	// content and it wraps whatever it is given in an entry of its own, so handing it a whole
	// core.Entry stored an entry whose content was an entry: a client that appended "inspection
	// complete" read back an object with a timestamp and a user id nested inside it, and a text
	// search over entry content was searching the printed form of a struct.
	entryIndex := -1
	err := server.changeNode(request.Path, userID, core.WritePermission, func(node *core.Node) error {
		if err := node.AppendToEvent(request.EventID, userID, request.Content, request.Metadata); err != nil {
			return apiErrorf(http.StatusInternalServerError, "Failed to append to event: %v", err)
		}

		// Read back INSIDE the hold: the index of what was just appended is only this entry's index
		// for as long as nothing else appends.
		entryIndex = len(node.Events[request.EventID].Entries) - 1
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	announced := mutation(mutationEntryAdded, request.Path)
	announced.EventID = request.EventID
	announced.EntryIndex = entryIndex
	server.publish(announced)
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

	// PROJECTED INSIDE THE HOLD: an entry carries attachments, and an attachment carries the file's
	// bytes. GetEventEntries copies the SLICE, but every entry in it still points at the forest's
	// own metadata map, so projecting after the hold was released was a read of a live map.
	var entries []entryView
	err := server.readNode(request.Path, userID, core.ReadPermission, func(node *core.Node) error {
		found, err := node.GetEventEntries(request.EventID)
		if err != nil {
			return apiErrorf(http.StatusInternalServerError, "%v", err)
		}
		entries = newEntryViews(found)
		return nil
	})
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

	// PROJECTED, not encoded directly: a node carries its users and a user carries a bcrypt hash.
	//
	// The projection is built under the READ hold and encoded outside it. Projecting walks every
	// map in the graph, which is exactly the read that must not run beside a mutation; the view it
	// produces COPIES every map and slice it exposes, so the encoding afterwards is over a value
	// nothing else can reach and a slow client cannot hold up a writer. See forest_projection.go —
	// the copies are the whole reason encoding outside the hold is allowed.
	var view nodeView
	server.readForest(func() {
		view = newNodeView(server.forest, userID)
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(view)
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

	startTime, endTime, err := plannedSpan(request.EventID, request.StartTime, request.EndTime)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	// Checked HERE as well as inside PlanEvent, so that "you may not" answers 403 rather than the
	// 500 every refusal used to be reported as. PERSISTED inside the same hold: a planned event
	// that is never written to the state file is gone on the next start, which is the whole span of
	// time a plan is for.
	err = server.changeNode(request.Path, userID, core.WritePermission, func(node *core.Node) error {
		err := node.PlanEvent(request.EventID, userID, &startTime, &endTime, request.Metadata)
		// A CONFLICT, not a success and not a server failure. This route was an upsert: planning
		// over an id that is already a live event answered 200 and wrote a plan into PlannedEvents
		// that /events and /query then dropped in favour of the live event — the write was
		// accepted and immediately unobservable.
		if errors.Is(err, core.ErrEventAlreadyStarted) {
			return apiErrorf(http.StatusConflict,
				"Event %q has already started on this node: a plan cannot be made for it",
				request.EventID)
		}
		if err != nil {
			return apiErrorf(http.StatusInternalServerError, "%v", err)
		}
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	announced := mutation(mutationEventPlanned, request.Path)
	announced.EventID = request.EventID
	server.publish(announced)
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
