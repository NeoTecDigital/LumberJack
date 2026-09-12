// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// A handle is (Runtime, principal). The runtime is shared and refcounted; the principal is what one
// handle acts as. Every method binds the handle's principal to the engine call it delegates, so an
// embedder never passes a user id and cannot pass the wrong one.
package embedded

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/types"
)

// ErrClosed is what a mutating method answers once its handle has been Closed. A Close tears the
// runtime down on the last reference — the engine is shut down and the sidecar flock RELEASED, so
// the path is free for another process to take — and a write that ran on afterwards would reach the
// state file the released lock no longer guards. A closed handle refuses rather than write behind a
// lock someone else may now hold.
var ErrClosed = errors.New("lumberjack: handle is closed")

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
	// done is set the instant Close is entered, BEFORE the runtime is torn down. Every mutating
	// method reads it first, so once a handle is closed its writes refuse rather than race the
	// teardown that releases the flock they would otherwise write behind.
	done atomic.Bool
}

// Close releases this handle, ONCE. The runtime it shared is torn down only when the LAST handle over
// its path closes; a Close is safe to call once per Open, and a second Close on the same handle is a
// no-op returning the first's result — never an error, and never a second decref that would steal the
// reference another live handle still holds.
func (h *Handle) Close() error {
	h.closeOnce.Do(func() {
		// Mark closed BEFORE the teardown, so a write racing this Close sees the handle closed the
		// moment the teardown begins rather than slipping past a check that is still open.
		h.done.Store(true)
		h.closeErr = h.runtime.close()
	})
	return h.closeErr
}

// ensureOpen refuses a call on a handle that has been Closed. It guards the MUTATORS — the operations
// that reach the state file the sidecar flock guards. What a closed handle's reads do is not one rule
// but three:
//
//   - Forest, Query, Aggregate and EventEntries answer from the forest still in memory: a FROZEN
//     snapshot, with NO staleness signal. Once the last Close released the flock another process may
//     own the path and be rewriting the file, and these reads say nothing about it.
//   - StatusOf routes through the worker pool, which the teardown stopped, and returns an error.
//   - PollMutations returns at once on the closed shutdown signal, with only what the frozen ring
//     holds after the cursor.
//
// The reads are left to answer rather than refused because Forest has no error return: refusing it
// means changing its signature, and refusing the other three while it still answers would be a
// fourth rule. An embedder that must not read a frozen forest does not read through a handle it has
// closed; ErrClosed from any mutator is the signal that the handle is one.
func (h *Handle) ensureOpen() error {
	if h.done.Load() {
		return ErrClosed
	}
	return nil
}

// Epoch is this run's sequence numbering. A cursor is only meaningful against the epoch it was issued
// under — across a restart the numbering starts afresh, and a caller comparing epochs learns to
// re-derive its view rather than resume a cursor that now means something else.
func (h *Handle) Epoch() uint64 {
	return h.runtime.epoch
}

// CreateNode makes the node a path names and returns where it lives.
func (h *Handle) CreateNode(request CreateNodeRequest) (NodeAnswer, error) {
	if err := h.ensureOpen(); err != nil {
		return NodeAnswer{}, err
	}
	return h.runtime.server.CreateNode(h.principal, request)
}

// PlanEvent schedules a future event and returns the mutation it announced.
func (h *Handle) PlanEvent(request PlanEventRequest) (MutationEvent, error) {
	if err := h.ensureOpen(); err != nil {
		return MutationEvent{}, err
	}
	return h.runtime.server.PlanEvent(h.principal, request)
}

// StartEvent opens an event on a leaf and returns the mutation it announced.
func (h *Handle) StartEvent(request StartEventRequest) (MutationEvent, error) {
	if err := h.ensureOpen(); err != nil {
		return MutationEvent{}, err
	}
	return h.runtime.server.StartEvent(h.principal, request)
}

// AppendToEvent adds one entry to a live event and returns the mutation it announced.
func (h *Handle) AppendToEvent(request AppendEventRequest) (MutationEvent, error) {
	if err := h.ensureOpen(); err != nil {
		return MutationEvent{}, err
	}
	return h.runtime.server.AppendToEvent(h.principal, request)
}

// EndEvent finishes an event and returns the mutation it announced.
func (h *Handle) EndEvent(request EndEventRequest) (MutationEvent, error) {
	if err := h.ensureOpen(); err != nil {
		return MutationEvent{}, err
	}
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

// MutationBatch is the answer of a poll: the events after the cursor, this run's epoch, whether the
// caller is caught up, and the oldest sequence the ring still holds.
//
// When CaughtUp is false the caller fell off the back of the ring; Oldest is where it resumes after
// re-deriving its view. Epoch pins the numbering — a batch from a different run is a gap of its own,
// because sequences live only in memory and start afresh on every open.
type MutationBatch struct {
	Events   []MutationEvent
	Epoch    uint64
	CaughtUp bool
	Oldest   uint64
}

// PollMutations reads the mutations after a cursor, blocking up to timeout for one to appear if none
// has.
//
// A Close returns a blocked poll at once, not after timeout: the runtime's shutdown signal is passed
// down as the poll's cancel.
func (h *Handle) PollMutations(after uint64, timeout time.Duration) MutationBatch {
	events, caughtUp, oldest := h.runtime.server.PollMutationsBlocking(after, timeout, h.runtime.closed)
	return MutationBatch{Events: events, Epoch: h.runtime.epoch, CaughtUp: caughtUp, Oldest: oldest}
}
