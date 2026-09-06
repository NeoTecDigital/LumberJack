package internal

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// The listing routes. Each one is a QUERY, not a second implementation of one.
//
// GET /events is the primitive that was missing. POST /events needs an event_id the caller must
// already possess, so there was no way to find out what events exist — which is why a client had to
// keep its open events in a browser variable that died on refresh.

// GET /events?scope=&status=&limit=&cursor=
func (server *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	request := queryRequest{
		Select: selectEvents,
		Scope:  r.URL.Query().Get("scope"),
		Where:  &whereClause{Status: splitList(r.URL.Query().Get("status"))},
		Sort:   []sortField{{Field: timeFieldCreatedAt, Dir: sortDescending}},
		Page:   pageFromQuery(r),
	}

	answerQuery(w, server, userID, request)
}

// GET /entries?scope=&since=&limit=&cursor= — the feed primitive.
//
// `since` is a lower bound on the entry's own timestamp, which is what a feed polls with: give me
// what has happened since the last thing I saw. Ascending, because a feed is read forwards.
func (server *Server) handleListEntries(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	request := queryRequest{
		Select: selectEntries,
		Scope:  r.URL.Query().Get("scope"),
		Where:  &whereClause{Time: &timeClause{Field: timeFieldTimestamp, From: r.URL.Query().Get("since")}},
		Sort:   []sortField{{Field: timeFieldTimestamp, Dir: sortAscending}},
		Page:   pageFromQuery(r),
	}

	answerQuery(w, server, userID, request)
}

// GET /nodes/{path} — one node, projected, without pulling the whole forest.
//
// The answer is the node ITSELF plus a one-level list of what is under it. newNodeView projects a
// node and everything beneath it, which is the right answer for GET /forest and the wrong one here:
// the point of this route is not to transfer a subtree.
func (server *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	// The path is accepted in either form and ANSWERED in the canonical one, so what this route
	// emits can be fed straight back to it and to /query's scope. See node_path.go.
	path := mux.Vars(r)["path"]

	var answer map[string]interface{}
	err := server.readNode(path, userID, core.ReadPermission, func(node *core.Node) error {
		answer = nodeDetail(node, server.canonicalPath(path))
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(answer)
}

// nodeDetail projects one node and names its children without descending into them.
//
// The caller must hold the forest for reading.
func nodeDetail(node *core.Node, path string) map[string]interface{} {
	summary := nodeCandidate(visit{node: node, path: path}).View.(nodeSummaryView)

	children := make([]map[string]interface{}, 0, len(node.Children))
	for _, child := range childrenByName(node) {
		children = append(children, map[string]interface{}{
			"id":   child.ID,
			"name": child.Name,
			"path": path + "/" + child.Name,
			"type": nodeTypeName(child.Type),
		})
	}

	events := make([]interface{}, 0, len(node.Events))
	for _, item := range eventCandidates(visit{node: node, path: path}) {
		events = append(events, item.View)
	}

	return map[string]interface{}{
		"node":     summary,
		"children": children,
		"events":   events,
		"users":    newUserViews(node.Users),
		"entries":  newEntryViews(node.Entries),
	}
}

// answerQuery runs a query built by a listing route and writes the answer.
func answerQuery(w http.ResponseWriter, server *Server, userID string, request queryRequest) {
	response, err := server.runQuery(userID, request)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// pageFromQuery reads a page out of a query string. An absent limit takes the default.
func pageFromQuery(r *http.Request) *pageRequest {
	page := &pageRequest{Cursor: r.URL.Query().Get("cursor")}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		// A limit that is not a number is left at zero, which paginate reads as "the default". It
		// is not an error worth refusing a listing over.
		if parsed, err := parsePositiveInt(limit); err == nil {
			page.Limit = parsed
		}
	}
	return page
}

// splitList reads a comma-separated query parameter. An empty parameter is no constraint.
func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

// parsePositiveInt reads a count out of a query string.
func parsePositiveInt(value string) (int, error) {
	parsed := 0
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, apiErrorf(http.StatusBadRequest, "%q is not a count", value)
		}
		parsed = parsed*10 + int(digit-'0')
		if parsed > maxPageLimit {
			return maxPageLimit, nil
		}
	}
	return parsed, nil
}
