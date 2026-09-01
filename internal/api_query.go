package internal

import (
	"encoding/json"
	"net/http"
)

// POST /query — the one coherent question-asking surface over nodes, events and entries.
//
// THE GAP THIS CLOSES: every other route either returns the whole forest or returns one thing by
// id. There was no filtering, no range, no sorting, no page and no search — and POST /events needed
// an event_id the caller had to already possess, so an event could not be DISCOVERED at all. That
// is why a client had to keep its open events in a browser variable that died on refresh.
//
// Four properties this route holds, in the order they are enforced:
//
//  1. The forest is held for READING for the whole gather, and every result is a PROJECTION that
//     does not point back into it. Nothing here can serialize a node another request is writing.
//  2. Every node is permission-filtered with CheckPermission(userID, Read). A caller sees what it
//     was granted and not one node more.
//  3. The walk is over a MULTI-PARENT DAG: a node reachable by two paths is counted once, and a
//     cycle terminates. See query_walk.go.
//  4. The page is cursor-based, not offset-based. See query_page.go.

func (server *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request queryRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response, err := server.runQuery(userID, request)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// runQuery is the route's whole body, separated from the HTTP of it so the discovery routes in
// api_discovery.go are the same query rather than a second implementation of one.
func (server *Server) runQuery(userID string, request queryRequest) (*queryResponse, error) {
	// selectTime is on this list because the gatherer has always produced time spans and /aggregate
	// has always accepted them — /query alone refused the word, so the one surface that can page,
	// filter and sort tracked time answered 400 for it. A capability that exists and cannot be
	// asked for is the same defect as a route that answers 200 and stores nothing.
	if !validSelect(request.Select, selectNodes, selectEvents, selectEntries, selectTime) {
		return nil, apiErrorf(http.StatusBadRequest,
			"select must be %q, %q, %q or %q", selectNodes, selectEvents, selectEntries, selectTime)
	}

	// EVERYTHING that can be rejected is rejected before the forest is touched. A caller that
	// misspelled a sort field learns so without the server having walked the tree for it.
	filter, err := compilePredicate(request.Where)
	if err != nil {
		return nil, err
	}
	order, err := compileOrdering(request.Sort)
	if err != nil {
		return nil, err
	}
	if _, err := decodeCursor(order, cursorOf(request.Page)); err != nil {
		return nil, err
	}

	matches, err := server.matching(userID, request.Select, request.Scope, request.Depth, filter)
	if err != nil {
		return nil, err
	}

	page, next, total, err := paginate(matches, order, request.Page)
	if err != nil {
		return nil, err
	}

	// A page is a LIST, empty or not. A client that has to check for null before iterating an empty
	// answer has been handed a second thing to get wrong.
	results := make([]interface{}, 0, len(page))
	for _, item := range page {
		results = append(results, item.View)
	}

	return &queryResponse{Results: results, NextCursor: next, Total: total}, nil
}

// matching gathers and filters, with the forest held for reading across both.
func (server *Server) matching(userID, selecting, scope string, depth *int, filter *predicate) ([]candidate, error) {
	var gathered []candidate
	var err error

	server.readForest(func() {
		gathered, err = server.gather(userID, selecting, scope, depth)
	})
	if err != nil {
		return nil, err
	}

	matches := make([]candidate, 0, len(gathered))
	for _, item := range gathered {
		if filter.match(item) {
			matches = append(matches, item)
		}
	}
	return matches, nil
}

// cursorOf reads the cursor out of an optional page, so an absent page is not a nil dereference.
func cursorOf(page *pageRequest) string {
	if page == nil {
		return ""
	}
	return page.Cursor
}
