package core

import (
	"errors"
	"fmt"
)

// WHERE AN ENTRY LIVES, and the one enumeration that knows all of it.
//
// A node keeps entries in three places — its own slice, the entries of each live event, and the
// entries of each plan — and the three are written by different routes. attachment_locate.go was
// written after a lookup that knew about one holder and a delete that knew about another shipped as
// a write-only route; the same shape is avoided here by construction. The backfill that gives old
// entries an identity, the lookup that resolves one by id, and the delete that removes one all walk
// entryRuns, so they cannot come to disagree about where an entry can be.
//
// AN ENTRY IS ADDRESSED BY ID, NOT BY INDEX. That is the whole reason this file exists: an index is
// invalidated by every insertion and every deletion before it, so a delete keyed on an index
// deletes whatever has since slid into that position. The id is minted at creation and never moves.

// ErrEntryNotFound is the sentinel a route answers 404 for. A SENTINEL rather than a formatted
// string, for the same reason ErrAttachmentNotFound is one: "there is no such entry" is not a
// server failure, and answering 500 tells a client to retry something that can never succeed.
var ErrEntryNotFound = errors.New("entry not found")

// ErrEntryIsTimeSpanSentinel refuses the removal of HALF a time span.
//
// A tracked span is a pair of entries — a start and the stop that closes it — and the pairing is
// positional: GetTimeTrackingSummary walks the node's entries and closes the open start of that
// user with the next stop it meets. Remove the stop alone and the start that was closed by it is
// re-paired with a LATER stop, silently lengthening a span nobody edited. So a sentinel is not
// deletable as an entry; the span is the unit, and DELETE /time/{id} is where it is removed.
var ErrEntryIsTimeSpanSentinel = errors.New("entry is part of a tracked time span")

// ErrTimeSpanNotFound is what an id that does not open a span is refused with.
var ErrTimeSpanNotFound = errors.New("time span not found")

// The holders a node has. Named, because a location is reported and a bare index is not readable.
const (
	EntryOnNode         = "node"
	EntryOnEvent        = "event"
	EntryOnPlannedEvent = "planned_event"
)

// EntryLocation is where on a node one entry is kept.
type EntryLocation struct {
	Holder     string `json:"holder"`
	EventID    string `json:"event_id,omitempty"`
	EntryIndex int    `json:"entry_index"`
}

// entryRun is one run of entries a node keeps, together with the only way to store a change to it.
//
// The store is what keeps a change visible: an Event is a VALUE in the map, so the event read out
// of it is a copy, and writing the copy back is what says the change was meant. The node's own
// entries are a field and are stored by assignment.
type entryRun struct {
	location EntryLocation
	entries  []Entry
	store    func([]Entry)
}

// entryRuns is EVERY place this node keeps entries, in a fixed order.
//
// Ordered so that two identical requests answer identically: ranging a Go map is deliberately
// randomized, and the same id can only be in one run, but the LOCATION reported for a scan and the
// order a backfill assigns derived ids in must not move between two reads of the same forest.
//
// The caller must hold the node.
func (n *Node) entryRuns() []entryRun {
	runs := []entryRun{{
		location: EntryLocation{Holder: EntryOnNode},
		entries:  n.Entries,
		store:    func(entries []Entry) { n.Entries = entries },
	}}

	runs = append(runs, eventEntryRuns(n.Events, EntryOnEvent)...)
	return append(runs, eventEntryRuns(n.PlannedEvents, EntryOnPlannedEvent)...)
}

// eventEntryRuns is the entry run of every event in a map, in id order.
func eventEntryRuns(events map[string]Event, holder string) []entryRun {
	runs := make([]entryRun, 0, len(events))
	for _, eventID := range sortedEventKeys(events) {
		event := events[eventID]
		runs = append(runs, entryRun{
			location: EntryLocation{Holder: holder, EventID: eventID},
			entries:  event.Entries,
			store: func(entries []Entry) {
				event.Entries = entries
				events[eventID] = event
			},
		})
	}
	return runs
}

// FindEntry resolves an id ANYWHERE on this node and says where it found it.
//
// The entry comes back as a COPY whose metadata and attachments are the stored ones: callers that
// project it must go through the projections in api_views.go, which copy everything they expose.
func (n *Node) FindEntry(entryID string) (*Entry, EntryLocation, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for _, run := range n.entryRuns() {
		for index := range run.entries {
			if run.entries[index].ID != entryID {
				continue
			}
			found := run.entries[index]
			at := run.location
			at.EntryIndex = index
			return &found, at, nil
		}
	}
	return nil, EntryLocation{}, fmt.Errorf("%w: %s", ErrEntryNotFound, entryID)
}

// DeleteEntry removes the entry an id names, wherever on this node it is kept.
//
// A TIME-TRACKING SENTINEL IS REFUSED. Removing one end of a span re-pairs the other end with a
// neighbouring one, which changes a duration nobody edited — see ErrEntryIsTimeSpanSentinel. The
// span is removed as a span by DeleteTimeSpan.
func (n *Node) DeleteEntry(entryID string, userID string) (EntryLocation, error) {
	if !n.CheckPermission(userID, WritePermission) {
		return EntryLocation{}, fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	for _, run := range n.entryRuns() {
		for index := range run.entries {
			if run.entries[index].ID != entryID {
				continue
			}
			if isTimeSentinel(run.entries[index]) {
				return EntryLocation{}, fmt.Errorf("%w: %s", ErrEntryIsTimeSpanSentinel, entryID)
			}

			at := run.location
			at.EntryIndex = index
			run.store(withoutEntries(run.entries, map[string]bool{entryID: true}))
			return at, nil
		}
	}
	return EntryLocation{}, fmt.Errorf("%w: %s", ErrEntryNotFound, entryID)
}

// DeleteTimeSpan removes a tracked span: the start an id names, and the stop that closes it.
//
// The pairing is READ THE WAY THE READERS READ IT. GetTimeTrackingSummary and timeSpanCandidates
// both walk the entries forward holding one open start per user, so a later start by the same user
// SUPERSEDES an earlier one and the earlier start is closed by nothing. A span whose start has been
// superseded, or which has not been stopped yet, is a start alone — removing it removes one entry,
// and that is a running timer being cancelled rather than a span being edited.
//
// It reports how many entries it removed.
func (n *Node) DeleteTimeSpan(startEntryID string, userID string) (int, error) {
	if !n.CheckPermission(userID, WritePermission) {
		return 0, fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	start := indexOfEntry(n.Entries, startEntryID)
	if start < 0 || n.Entries[start].Content != TimeEntryStart {
		return 0, fmt.Errorf("%w: %s", ErrTimeSpanNotFound, startEntryID)
	}

	removing := map[string]bool{startEntryID: true}
	if stop := n.Entries[start].closedBy(n.Entries[start+1:]); stop != "" {
		removing[stop] = true
	}

	n.Entries = withoutEntries(n.Entries, removing)
	return len(removing), nil
}

// closedBy is the id of the stop that closes this start, or "" if nothing does.
//
// `later` is the entries after the start, in order. A start by the same user takes the open slot,
// which is what the summary readers do, so anything past it closes that one and not this.
func (e Entry) closedBy(later []Entry) string {
	for _, entry := range later {
		if entry.UserID != e.UserID {
			continue
		}
		switch entry.Content {
		case TimeEntryStart:
			return ""
		case TimeEntryStop:
			return entry.ID
		}
	}
	return ""
}

// isTimeSentinel reports whether an entry is one half of a tracked span.
func isTimeSentinel(entry Entry) bool {
	return entry.Content == TimeEntryStart || entry.Content == TimeEntryStop
}

// indexOfEntry is where an id sits in a run, or -1.
func indexOfEntry(entries []Entry, entryID string) int {
	for index := range entries {
		if entries[index].ID == entryID {
			return index
		}
	}
	return -1
}

// withoutEntries is a run with every named id gone.
//
// A FRESH slice, not a filter in place: the run may share its backing array with a copy of the
// event that holds it, and rewriting that array underneath the copy is a change nobody asked for.
// This is the same rule withoutAttachment follows, for the same reason.
func withoutEntries(entries []Entry, removing map[string]bool) []Entry {
	kept := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if !removing[entry.ID] {
			kept = append(kept, entry)
		}
	}
	return kept
}
