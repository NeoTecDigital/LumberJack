// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The event lifecycle, separated from the HTTP that carries it.
//
// Each of these functions IS the route's whole body — validate, take the exclusive hold, mutate,
// persist, announce — with the request/response types NAMED rather than anonymous. An anonymous
// struct cannot be named at a second call site, which is exactly what stopped the embedded API from
// reusing a handler; a named one can, so HTTP and the embedded surface run the same code and cannot
// drift. The `json:` tags are unchanged, because ~200 route tests assert on the JSON bodies.
//
// The publish moves INSIDE each function and each returns the event it announced: neither entry
// point can forget to announce, both announce identically, and a caller receives the value rather
// than reconstructing it. Ordering is preserved — publish still happens after the persist that
// changeNode performs, never before. See mutation_stream.go.
package internal

import (
	"errors"
	"net/http"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// planEventRequest is the body of POST /events/plan.
type planEventRequest struct {
	Path      string                 `json:"path"`
	EventID   string                 `json:"event_id"`
	StartTime string                 `json:"start_time"`
	EndTime   string                 `json:"end_time"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// planEvent schedules a future event and announces the plan.
func (server *Server) planEvent(userID string, request planEventRequest) (mutationEvent, error) {
	startTime, endTime, err := plannedSpan(request.EventID, request.StartTime, request.EndTime)
	if err != nil {
		return mutationEvent{}, err
	}

	// Checked HERE as well as inside PlanEvent, so that "you may not" answers 403 rather than the
	// 500 every refusal used to be reported as. PERSISTED inside the same hold: a planned event
	// that is never written to the state file is gone on the next start, which is the whole span of
	// time a plan is for.
	err = server.changeNode(request.Path, userID, core.WritePermission, func(node *core.Node) error {
		err := node.PlanEvent(request.EventID, userID, &startTime, &endTime, request.Metadata)
		// A CONFLICT, not a success and not a server failure. This route was an upsert: planning
		// over an id that is already a live event answered 200 and wrote a plan into PlannedEvents
		// that /events and /query then dropped in favour of the live event — the write was accepted
		// and immediately unobservable.
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
		return mutationEvent{}, err
	}

	announced := mutation(mutationEventPlanned, request.Path)
	announced.EventID = request.EventID
	return server.publish(announced), nil
}

// startEventRequest is the body of POST /events/start.
type startEventRequest struct {
	Path     string                 `json:"path"`
	EventID  string                 `json:"event_id"`
	Metadata map[string]interface{} `json:"metadata"`
}

// startEvent opens an event on a leaf and announces that it began.
func (server *Server) startEvent(userID string, request startEventRequest) (mutationEvent, error) {
	if !validEventID(request.EventID) {
		return mutationEvent{}, apiErrorf(http.StatusBadRequest, eventIDRequired)
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
		return mutationEvent{}, err
	}

	announced := mutation(mutationEventStarted, request.Path)
	announced.EventID = request.EventID
	return server.publish(announced), nil
}

// endEventRequest is the body of POST /events/end.
type endEventRequest struct {
	Path    string `json:"path"`
	EventID string `json:"event_id"`
}

// endEvent finishes an event and announces that it ended.
func (server *Server) endEvent(userID string, request endEventRequest) (mutationEvent, error) {
	// The same guard /events/start and /events/plan have, missing here: an end with no event_id
	// looked up the empty string, which core answered as "event not found" — a 500 for a request
	// that named nothing, where the caller made the mistake and should be told 400.
	if !validEventID(request.EventID) {
		return mutationEvent{}, apiErrorf(http.StatusBadRequest, eventIDRequired)
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
		return mutationEvent{}, err
	}

	announced := mutation(mutationEventEnded, request.Path)
	announced.EventID = request.EventID
	return server.publish(announced), nil
}

// appendEventRequest is the body of POST /events/append.
type appendEventRequest struct {
	Path     string                 `json:"path"`
	EventID  string                 `json:"event_id"`
	Content  string                 `json:"content"`
	Metadata map[string]interface{} `json:"metadata"`
}

// appendToEvent adds one entry to a live event and announces it. The announced event carries the
// entry's id and index and the canonical node path, which is everything the HTTP response answers —
// so a caller reads the acknowledgement off the returned value rather than rebuilding it.
func (server *Server) appendToEvent(userID string, request appendEventRequest) (mutationEvent, error) {
	// The CONTENT is passed, not an Entry built around it. AppendToEvent's third argument IS the
	// content and it wraps whatever it is given in an entry of its own, so handing it a whole
	// core.Entry stored an entry whose content was an entry: a client that appended "inspection
	// complete" read back an object with a timestamp and a user id nested inside it, and a text
	// search over entry content was searching the printed form of a struct.
	entryIndex := -1
	entryID := ""
	err := server.changeNode(request.Path, userID, core.WritePermission, func(node *core.Node) error {
		if err := node.AppendToEvent(request.EventID, userID, request.Content, request.Metadata); err != nil {
			return apiErrorf(http.StatusInternalServerError, "Failed to append to event: %v", err)
		}

		// Read back INSIDE the hold: the index of what was just appended is only this entry's index
		// for as long as nothing else appends. The ID read here is why that no longer matters to
		// anyone downstream — it names this entry after the index has moved on.
		id, index, err := appendedEntry(node, request.EventID)
		if err != nil {
			return err
		}
		entryID, entryIndex = id, index
		return nil
	})
	if err != nil {
		return mutationEvent{}, err
	}

	// The id is ANSWERED, not only announced. A client that has just posted a message needs to be
	// able to name it — to edit it, delete it or be replied to — without going back to the feed and
	// guessing which of the entries there is the one it wrote.
	announced := mutation(mutationEntryAdded, request.Path)
	announced.EventID = request.EventID
	announced.EntryIndex = entryIndex
	announced.EntryID = entryID
	return server.publish(announced), nil
}

// appendedEntry names the entry that was just appended, read back under the caller's hold.
//
// It GUARDS the read that used to index blindly. `node.Events[eventID]` is a map lookup, and a miss
// yields a zero Event whose Entries is nil; `len(nil) - 1` is -1, and indexing a slice at -1 is a
// panic, not an error. AppendToEvent's own contract makes the entry present when it returns nil, so
// this is a fault of the server if it fires — a 500 — but it is answered, not thrown, because a
// panic in a handler under a C caller is a crashed process rather than a failed call.
func appendedEntry(node *core.Node, eventID string) (id string, index int, err error) {
	event, ok := node.Events[eventID]
	if !ok || len(event.Entries) == 0 {
		return "", -1, apiErrorf(http.StatusInternalServerError,
			"event %q holds no entry to acknowledge after an append", eventID)
	}
	index = len(event.Entries) - 1
	return event.Entries[index].ID, index, nil
}

// eventEntriesRequest is the body of POST /events.
type eventEntriesRequest struct {
	Path    string `json:"path"`
	EventID string `json:"event_id"`
}

// eventEntries projects the entries of one event under a read hold.
//
// It asked for NOTHING originally: no caller, no permission. core.GetEventEntries checks neither,
// so any valid session could read the entries of any event on any node regardless of what it had
// been granted. Reading is a ReadPermission act and is checked as one.
func (server *Server) eventEntries(userID string, request eventEntriesRequest) ([]entryView, error) {
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
		return nil, err
	}
	return entries, nil
}
