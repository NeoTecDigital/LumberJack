// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The exported façade over the engine: the one surface an in-process embedder and the C ABI both
// call, so the HTTP routes and the embedded API cannot drift apart — they run the same code.
//
// THERE IS NO NEW LOGIC HERE. Every method decodes nothing, validates nothing and mutates nothing
// on its own; each is a thin delegation to a function that already carries the behaviour, the hold
// and the persist. Where a caller needs something the engine did not expose yet, that something was
// added to the layer below, not invented here.
//
// THE ALIAS TRICK is what makes this nearly free. Every request and view type in this package
// already has an unexported NAME and fully exported FIELDS — the json tags the ~200 route tests
// assert on are the single source of truth for both surfaces. So an alias, not a new type and not a
// conversion, exports the name while keeping the tags. Only nodeAnswer needs a real definition here,
// its fields being unexported; eventAddress is the other such type, but no exported method returns
// it, so it stays internal until one does.
package internal

import (
	"net/http"
)

// The request and view types, exported by ALIAS. `=` makes each the very same type, so a value built
// here and a value the routes decode are interchangeable and the json tags stay in one place.
type (
	CreateNodeRequest   = nodeRequest
	PlanEventRequest    = planEventRequest
	StartEventRequest   = startEventRequest
	EndEventRequest     = endEventRequest
	AppendEventRequest  = appendEventRequest
	EventEntriesRequest = eventEntriesRequest
	QueryRequest        = queryRequest
	QueryResponse       = queryResponse
	AggregateRequest    = aggregateRequest
	AggregateResponse   = aggregateResponse
	EntryView           = entryView
	NodeView            = nodeView
	MutationEvent       = mutationEvent
)

// NodeAnswer is what CreateNode reports: where the node it made now lives. It is a real definition,
// not an alias, because nodeAnswer's fields are unexported — this is the projection that exposes
// them, and it carries exactly what writeCreatedNode already answers over HTTP.
type NodeAnswer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path"`
}

// Status reports the HTTP status an apiError carries, so an embedder — and the C ABI's status enum —
// can map a failure to its meaning without parsing the message. An error with no status is the
// server's fault and is a 500, exactly writeAPIError's rule.
func (e *apiError) Status() int { return e.status }

// CreateNode makes the node a path names and returns where it lives.
func (server *Server) CreateNode(userID string, request CreateNodeRequest) (NodeAnswer, error) {
	nodeType, err := nodeTypeOf(request.Type)
	if err != nil {
		return NodeAnswer{}, apiErrorf(http.StatusBadRequest, "%v", err)
	}

	created, err := server.createNodeUnderHold(request.Path, nodeType, userID)
	if err != nil {
		return NodeAnswer{}, err
	}

	return NodeAnswer{
		ID:   created.id,
		Name: created.name,
		Type: nodeTypeName(created.nodeType),
		Path: server.canonicalPath(request.Path),
	}, nil
}

// PlanEvent schedules a future event and returns the mutation it announced.
func (server *Server) PlanEvent(userID string, request PlanEventRequest) (MutationEvent, error) {
	return server.planEvent(userID, request)
}

// StartEvent opens an event on a leaf and returns the mutation it announced.
func (server *Server) StartEvent(userID string, request StartEventRequest) (MutationEvent, error) {
	return server.startEvent(userID, request)
}

// AppendToEvent adds one entry to a live event and returns the mutation it announced — which carries
// the entry's id and index and the canonical node path.
func (server *Server) AppendToEvent(userID string, request AppendEventRequest) (MutationEvent, error) {
	return server.appendToEvent(userID, request)
}

// EndEvent finishes an event and returns the mutation it announced.
func (server *Server) EndEvent(userID string, request EndEventRequest) (MutationEvent, error) {
	return server.endEvent(userID, request)
}

// EventEntries projects the entries of one event, under a read permission check on the node.
func (server *Server) EventEntries(userID string, request EventEntriesRequest) ([]EntryView, error) {
	return server.eventEntries(userID, request)
}

// Query answers the one predicate surface over nodes, events, entries and time.
func (server *Server) Query(userID string, request QueryRequest) (*QueryResponse, error) {
	return server.runQuery(userID, request)
}

// Aggregate answers grouped counts and durations over the same predicate grammar as Query.
func (server *Server) Aggregate(userID string, request AggregateRequest) (*AggregateResponse, error) {
	return server.runAggregate(userID, request)
}

// Forest projects the whole forest as the caller may see it, filtered by what the caller may read.
func (server *Server) Forest(userID string) NodeView {
	return server.forestView(userID)
}

// StatusOf projects one subtree by path, filtered by what the caller may read. It is the embedded
// twin of GET /forest/tree: a 403 for a subtree the caller may not read is told apart from a 404 for
// one that is not there.
func (server *Server) StatusOf(userID, path string) (NodeView, error) {
	return server.queuedNodeView(path, userID)
}

// PollMutations reads the mutations after a cursor and whether the caller is caught up. caughtUp is
// false when the cursor is older than anything the ring still holds — a gap the caller must close by
// re-deriving its view, not an error to swallow.
func (server *Server) PollMutations(after uint64) ([]MutationEvent, bool) {
	return server.pollMutations(after)
}
