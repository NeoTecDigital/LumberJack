package core

import (
	"errors"
	"fmt"
)

// REMOVING AND CHANGING AN EVENT, and the one thing that decides WHICH event an id names.
//
// A node keeps events in TWO maps — Events for what is happening or has happened, PlannedEvents for
// what is intended — and the same id can be in both, because planning a meeting and then starting
// it writes the second without clearing the first. Every reader flattens the two and lets the live
// one win, which is the right answer for reading and the WRONG one for a delete: "the live one
// wins" applied to a removal silently leaves the plan behind, still visible in GET /forest, and
// answers 200 as though the thing the caller pointed at were gone.
//
// So the map is never inferred here. The caller says which, the routes above refuse an ambiguous id
// rather than choosing, and this file does exactly what it is told.

// ErrEventNotFound is the sentinel the routes answer 404 for.
var ErrEventNotFound = errors.New("event not found")

// ErrEventIDTaken refuses a rename onto an id the node already uses. An event id is the KEY of the
// map it lives in, so a rename onto a taken id is not a rename — it is an overwrite of somebody
// else's record, reported as a rename of yours.
var ErrEventIDTaken = errors.New("event id is already in use on this node")

// EventRemoval is what went with an event: its entries, and the files hanging off them.
type EventRemoval struct {
	Entries     int `json:"entries_removed"`
	Attachments int `json:"attachments_removed"`
}

// eventsOfKind is one of the two maps, named rather than guessed.
func (n *Node) eventsOfKind(planned bool) map[string]Event {
	if planned {
		return n.PlannedEvents
	}
	return n.Events
}

// HoldsEvent reports which of the two maps carry an id. Both may.
//
// The caller must hold the forest for reading.
func (n *Node) HoldsEvent(eventID string) (live bool, planned bool) {
	_, live = n.Events[eventID]
	_, planned = n.PlannedEvents[eventID]
	return live, planned
}

// DeleteEvent removes one event from one named map, and reports what went with it.
//
// AN EVENT'S ENTRIES GO WITH IT, and there is no mode for keeping them. An entry inside an event
// exists nowhere else — it is not addressable once the event is gone, it is not reachable by any
// route, and it is not a thing that can be re-parented — so keeping it would be keeping bytes no
// caller can ever see again. The attachments hanging off those entries go for the same reason: they
// are stored inside the entry, so their bytes leave with it.
func (n *Node) DeleteEvent(eventID string, planned bool, userID string) (EventRemoval, error) {
	if !n.CheckPermission(userID, WritePermission) {
		return EventRemoval{}, fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	events := n.eventsOfKind(planned)
	event, exists := events[eventID]
	if !exists {
		return EventRemoval{}, fmt.Errorf("%w: %s", ErrEventNotFound, eventID)
	}

	removed := EventRemoval{Entries: len(event.Entries)}
	for _, entry := range event.Entries {
		removed.Attachments += len(entry.Attachments)
	}

	delete(events, eventID)
	return removed, nil
}

// ChangeEvent applies a change to one stored event and stores the result back.
//
// The event is handed over as a POINTER TO A COPY and written back afterwards, because an Event is
// a value in a map: a change applied to what the map hands out is a change applied to a copy and
// then dropped. Every writer of an event in this package has the same shape for the same reason.
func (n *Node) ChangeEvent(eventID string, planned bool, userID string, change func(*Event) error) error {
	if !n.CheckPermission(userID, WritePermission) {
		return fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	events := n.eventsOfKind(planned)
	event, exists := events[eventID]
	if !exists {
		return fmt.Errorf("%w: %s", ErrEventNotFound, eventID)
	}

	if err := change(&event); err != nil {
		return err
	}
	events[eventID] = event
	return nil
}

// RenameEvent moves an event to a new id within the map it is already in.
//
// THE NEW ID MUST BE FREE IN BOTH MAPS, not just in the one being written. One id is one event on a
// node — that is the rule every reader already applies when it flattens the two maps — so renaming
// a plan onto the id of a live event would produce a plan that no reader will ever show again,
// which is the same accepted-and-invisible write POST /events/plan was fixed for.
func (n *Node) RenameEvent(from, to string, planned bool, userID string) error {
	if !n.CheckPermission(userID, WritePermission) {
		return fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	events := n.eventsOfKind(planned)
	event, exists := events[from]
	if !exists {
		return fmt.Errorf("%w: %s", ErrEventNotFound, from)
	}
	if _, live := n.Events[to]; live {
		return fmt.Errorf("%w: %s", ErrEventIDTaken, to)
	}
	if _, scheduled := n.PlannedEvents[to]; scheduled {
		return fmt.Errorf("%w: %s", ErrEventIDTaken, to)
	}

	delete(events, from)
	events[to] = event
	return nil
}
