// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// A handle is (Runtime, principal). The runtime is shared and refcounted; the principal is what one
// handle acts as. Every method binds the handle's principal to the engine call it delegates, so an
// embedder never passes a user id and cannot pass the wrong one.
package embedded

import (
	"sync"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/types"
)

// The config, request and view types are re-exported by ALIAS so an embedder imports only this
// package. `=` makes each the very same type, so a value built here is the value the engine uses.
type (
	Config              = types.ServerConfig
	CreateNodeRequest   = internal.CreateNodeRequest
	PlanEventRequest    = internal.PlanEventRequest
	StartEventRequest   = internal.StartEventRequest
	EndEventRequest     = internal.EndEventRequest
	AppendEventRequest  = internal.AppendEventRequest
	EventEntriesRequest = internal.EventEntriesRequest
	QueryRequest        = internal.QueryRequest
	QueryResponse       = internal.QueryResponse
	AggregateRequest    = internal.AggregateRequest
	AggregateResponse   = internal.AggregateResponse
	NodeAnswer          = internal.NodeAnswer
	NodeView            = internal.NodeView
	EntryView           = internal.EntryView
	MutationEvent       = internal.MutationEvent
)

// Handle is one principal's view of an open runtime. It is what Open returns and Close releases.
type Handle struct {
	runtime   *Runtime
	principal string
	closeOnce sync.Once
	closeErr  error
}

// Close releases this handle, ONCE. The runtime it shared is torn down only when the LAST handle over
// its path closes; a Close is safe to call once per Open, and a second Close on the same handle is a
// no-op returning the first's result — never an error, and never a second decref that would steal the
// reference another live handle still holds.
func (h *Handle) Close() error {
	h.closeOnce.Do(func() {
		h.closeErr = h.runtime.close()
	})
	return h.closeErr
}

// Epoch is this run's sequence numbering. A cursor is only meaningful against the epoch it was issued
// under — across a restart the numbering starts afresh, and a caller comparing epochs learns to
// re-derive its view rather than resume a cursor that now means something else.
func (h *Handle) Epoch() uint64 {
	return h.runtime.epoch
}

// CreateNode makes the node a path names and returns where it lives.
func (h *Handle) CreateNode(request CreateNodeRequest) (NodeAnswer, error) {
	return h.runtime.server.CreateNode(h.principal, request)
}

// PlanEvent schedules a future event and returns the mutation it announced.
func (h *Handle) PlanEvent(request PlanEventRequest) (MutationEvent, error) {
	return h.runtime.server.PlanEvent(h.principal, request)
}

// StartEvent opens an event on a leaf and returns the mutation it announced.
func (h *Handle) StartEvent(request StartEventRequest) (MutationEvent, error) {
	return h.runtime.server.StartEvent(h.principal, request)
}

// AppendToEvent adds one entry to a live event and returns the mutation it announced.
func (h *Handle) AppendToEvent(request AppendEventRequest) (MutationEvent, error) {
	return h.runtime.server.AppendToEvent(h.principal, request)
}

// EndEvent finishes an event and returns the mutation it announced.
func (h *Handle) EndEvent(request EndEventRequest) (MutationEvent, error) {
	return h.runtime.server.EndEvent(h.principal, request)
}

// EventEntries projects the entries of one event, under a read permission check on the node.
func (h *Handle) EventEntries(request EventEntriesRequest) ([]EntryView, error) {
	return h.runtime.server.EventEntries(h.principal, request)
}

// Query answers the one predicate surface over nodes, events, entries and time.
func (h *Handle) Query(request QueryRequest) (*QueryResponse, error) {
	return h.runtime.server.Query(h.principal, request)
}

// Aggregate answers grouped counts and durations over the same predicate grammar as Query.
func (h *Handle) Aggregate(request AggregateRequest) (*AggregateResponse, error) {
	return h.runtime.server.Aggregate(h.principal, request)
}

// Forest projects the whole forest as this principal may see it.
func (h *Handle) Forest() NodeView {
	return h.runtime.server.Forest(h.principal)
}

// StatusOf projects one subtree by path, as this principal may see it.
func (h *Handle) StatusOf(path string) (NodeView, error) {
	return h.runtime.server.StatusOf(h.principal, path)
}

// PollMutations reads the mutations after a cursor, blocking up to timeout for one to appear if none
// has, and returns this run's epoch and whether the caller is caught up.
//
// A Close returns a blocked poll at once, not after timeout: the runtime's shutdown signal is passed
// down as the poll's cancel. caughtUp is false when the cursor is older than the ring still holds — a
// gap the caller closes by re-deriving its view, and the reason the epoch is returned alongside.
func (h *Handle) PollMutations(after uint64, timeout time.Duration) (events []MutationEvent, epoch uint64, caughtUp bool) {
	events, caughtUp = h.runtime.server.PollMutationsBlocking(after, timeout, h.runtime.closed)
	return events, h.runtime.epoch, caughtUp
}
