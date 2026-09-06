package internal

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/NeoTecDigital/LumberJack/internal/core"
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
	// The opening entry's id is read back inside the hold, because it is the NAME OF THE SPAN: a
	// span is two entries read as a pair and is not stored, so the start's id is the only identity
	// it has, and DELETE /time/{id} takes exactly this one.
	spanID := ""
	err := server.changeNode(request.Path, userID, core.WritePermission, func(node *core.Node) error {
		started, err := node.StartTimeTracking(userID)
		if err != nil {
			return apiErrorf(http.StatusForbidden, "%v", err)
		}
		spanID = started.ID
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	announced := mutation(mutationEntryAdded, request.Path)
	announced.EntryID = spanID
	server.publish(announced)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":        spanID,
		"node_path": server.canonicalPath(request.Path),
	})
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
	stoppedID := ""
	err := server.changeNode(request.Path, userID, core.WritePermission, func(node *core.Node) error {
		stopped, err := node.StopTimeTracking(userID)
		if err != nil {
			return apiErrorf(http.StatusForbidden, "%v", err)
		}
		stoppedID = stopped.ID
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

	// The SAME session shape GET /time answers with, node_path included. One kind of thing gets one
	// shape: a client that reads a span here and a span there must not have to know which route it
	// came from to read it. `duration` is NANOSECONDS here too.
	trackedOn := server.canonicalPath(request.Path)
	for _, session := range summary {
		session["node_path"] = trackedOn
	}

	announced := mutation(mutationEntryAdded, request.Path)
	announced.EntryID = stoppedID
	server.publish(announced)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

// GET /time?scope=&depth= — every span tracked in a subtree.
//
// THE DEFECT: this was the ONE scoped route that did not mean a subtree. `scope` is "this node and
// everything under it" on /query, /aggregate, /entries and /events, and POST /query select=time
// already reports spans recursively — but GET /time read the named node alone, so a branch whose
// children had tracked hours all week answered []. A caller cannot tell that from "nobody tracked
// any time", which is worse than an error: it is a wrong answer with a success code.
//
// Resolved TOWARDS the rest of the API. The single-node reading is still available and is now
// something the caller ASKS for — depth=0 — rather than something it gets by surprise.
//
// UNITS: `duration` is NANOSECONDS. It is a Go time.Duration on the wire and has always been one;
// it is left exactly as it was. The same span is reported by POST /query select=time as
// `duration_ms` in MILLISECONDS, and by /aggregate as `duration_sum` in SECONDS. Three units for
// one quantity is a real trap and it is not one this route may quietly re-pick a side of, so every
// one of them is named where it is returned instead.
func (server *Server) handleGetTimeTracking(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	// A QUERY PARAMETER, not a JSON body. This is a GET; no conforming client sends a body on one,
	// so decoding one made the route unreachable — every caller got 400 "EOF".
	//
	// `scope` is the name every other scoped route uses. `path` is what this one has always taken
	// and keeps taking, because it means the same thing and clients send it.
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = r.URL.Query().Get("path")
	}

	depth, err := depthFromQuery(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	sessions, err := server.timeSessions(userID, scope, depth)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

// timeSessions is every closed span the caller tracked in a scope, each one saying which node it
// was tracked on.
//
// node_path is REQUIRED for the recursion to be usable: an answer gathered from many nodes whose
// items cannot be told apart is a list a client can display and not act on. It is the same field,
// under the same name, that /query select=time already puts on a span.
func (server *Server) timeSessions(userID, scope string, depth *int) ([]map[string]interface{}, error) {
	sessions := []map[string]interface{}{}

	var walkErr error
	server.readForest(func() {
		walkErr = server.walkScope(scope, depth, func(at visit) {
			// A node the caller may not read contributes nothing, and the walk goes on through it:
			// permission granted deeper down is not withdrawn by one never granted above.
			if !at.node.CheckPermission(userID, core.ReadPermission) {
				return
			}
			for _, session := range at.node.GetTimeTrackingSummary(userID) {
				session["node_path"] = at.path
				sessions = append(sessions, session)
			}
		})
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return sessions, nil
}

// depthFromQuery reads how far below the scope root a walk may go. Absent is unbounded, which is
// what every other scoped route means by an absent depth.
//
// NOT parsePositiveInt: that one silently caps at the page limit, which is the right thing for a
// page size and the wrong thing for a depth — a bound quietly replaced by a smaller one hides part
// of the forest and says nothing. A negative depth is refused by walkScope, which is where every
// caller of it gets the same refusal.
func depthFromQuery(r *http.Request) (*int, error) {
	raw := r.URL.Query().Get("depth")
	if raw == "" {
		return nil, nil
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return nil, apiErrorf(http.StatusBadRequest, "depth must be a whole number")
	}
	return &parsed, nil
}
