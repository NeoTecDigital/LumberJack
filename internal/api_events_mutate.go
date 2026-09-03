package internal

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/vaziolabs/lumberjack/internal/core"
)

// DELETE /events/{id} and PATCH /events/{id} — cancelling a meeting, and moving one.
//
// WHICH EVENT AN ID NAMES. A node keeps events in two maps and the same id can be in both: planning
// an event and then starting it writes Events without clearing PlannedEvents, so the ordinary
// lifecycle produces the ambiguity. Every READER flattens the two and lets the live one win, which
// is right for reading and wrong for writing — "the live one wins" applied to a delete leaves the
// plan behind, still visible in GET /forest, under a 200 that said it was gone. So these routes
// REFUSE an ambiguous id and name the parameter that resolves it, and the answer always says which
// map it acted on. A caller is never told "deleted" without being told what was deleted.
//
// WHY PATCH EXISTS AT ALL. POST /events/plan is an UPSERT WITH REPLACE SEMANTICS: re-planning an id
// overwrites the whole record, so a call that omits `metadata` clears it, and moving a meeting by a
// day means re-sending everything the event ever carried or silently losing it. The frontend
// measured exactly that and wrote it down. PATCH MERGES: a field that is not in the body is not
// changed, and — following PATCH /nodes/{path}/metadata, so there is one rule for this in the whole
// API — a metadata key set to null is deleted, which is the only way a merge can remove anything.
//
// WHAT PATCH WILL NOT DO: change an event's STATUS. Status is what /events/start and /events/end
// mean, and a second way to move an event through its lifecycle is a second set of rules about when
// an end time may exist. So setting `end_time` on an ONGOING event is refused and names
// POST /events/end; setting it on a plan, or correcting it on an event that has already finished,
// is what this route is for.
//
// TYPED FIELDS ARE SET AS THEMSELVES. StartEvent derives Category, Frequency and Pattern out of
// metadata keys, which left them unreachable to a planned event and made a metadata key silently
// mean two things. Here they are their own fields: `category` sets Category and `metadata.category`
// sets a metadata key, and neither reaches across into the other.

// The two maps, as a caller names them.
const (
	eventKindLive    = "live"
	eventKindPlanned = "planned"
)

// eventAddress is which event, on which node, in which map.
type eventAddress struct {
	path    string
	eventID string
	planned bool
	kind    string
}

// handleDeleteEvent removes one event and everything stored inside it.
func (server *Server) handleDeleteEvent(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("DeleteEvent")
	defer server.logger.Exit("DeleteEvent")

	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	path := r.URL.Query().Get("path")
	eventID := mux.Vars(r)["id"]

	var at eventAddress
	var removed core.EventRemoval
	err := server.changeNode(path, userID, core.WritePermission, func(node *core.Node) error {
		resolved, err := addressEvent(node, path, eventID, r.URL.Query().Get("kind"))
		if err != nil {
			return err
		}
		at = resolved

		removed, err = node.DeleteEvent(at.eventID, at.planned, userID)
		return asEventError(err)
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	announced := mutation(mutationEventDeleted, path)
	announced.EventID = eventID
	server.publish(announced)
	server.logger.Success("Deleted %s event %s on %s for %s", at.kind, eventID, path, userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"path":                server.canonicalPath(path),
		"event_id":            eventID,
		"kind":                at.kind,
		"entries_removed":     removed.Entries,
		"attachments_removed": removed.Attachments,
	})
}

// handleUpdateEvent renames and retimes an event without the replace-semantics upsert.
func (server *Server) handleUpdateEvent(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("UpdateEvent")
	defer server.logger.Exit("UpdateEvent")

	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var patch eventPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	path := r.URL.Query().Get("path")
	eventID := mux.Vars(r)["id"]

	at, view, err := server.applyEventPatch(path, eventID, r.URL.Query().Get("kind"), userID, patch)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	announced := mutation(mutationEventUpdated, path)
	announced.EventID = at.eventID
	if at.eventID != eventID {
		// A client watching the old id has no other way to learn that the event it is following is
		// the one that just appeared under a different name.
		announced.PreviousEventID = eventID
	}
	server.publish(announced)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"path": server.canonicalPath(path), "event_id": at.eventID, "kind": at.kind, "event": view,
	})
}

// applyEventPatch resolves the event, applies the merge, renames it if asked, and projects the
// result — all under one exclusive hold, so the answer describes the event this call produced and
// not one a later request changed.
func (server *Server) applyEventPatch(path, eventID, kind, userID string, patch eventPatch) (eventAddress, eventView, error) {
	var at eventAddress
	var view eventView

	err := server.changeNode(path, userID, core.WritePermission, func(node *core.Node) error {
		resolved, err := addressEvent(node, path, eventID, kind)
		if err != nil {
			return err
		}
		at = resolved

		if err := node.ChangeEvent(at.eventID, at.planned, userID, func(event *core.Event) error {
			return patch.applyTo(event, at.planned, userID)
		}); err != nil {
			return asEventError(err)
		}

		if err := patch.renameOn(node, &at, userID); err != nil {
			return err
		}

		view = newEventView(eventsOf(node, at.planned)[at.eventID])
		return nil
	})
	return at, view, err
}

// eventsOf is the map an address names, so the projection reads back the same one the change wrote.
func eventsOf(node *core.Node, planned bool) map[string]core.Event {
	if planned {
		return node.PlannedEvents
	}
	return node.Events
}

// addressEvent decides WHICH event an id names, and refuses rather than guessing.
//
// The caller must hold the forest.
func addressEvent(node *core.Node, path, eventID, kind string) (eventAddress, error) {
	live, planned := node.HoldsEvent(eventID)

	switch kind {
	case eventKindLive:
		if !live {
			return eventAddress{}, apiErrorf(http.StatusNotFound, "no live event %q on this node", eventID)
		}
		return eventAddress{path: path, eventID: eventID, planned: false, kind: eventKindLive}, nil
	case eventKindPlanned:
		if !planned {
			return eventAddress{}, apiErrorf(http.StatusNotFound, "no planned event %q on this node", eventID)
		}
		return eventAddress{path: path, eventID: eventID, planned: true, kind: eventKindPlanned}, nil
	case "":
		return unambiguousEvent(node, path, eventID, live, planned)
	default:
		return eventAddress{}, apiErrorf(http.StatusBadRequest,
			"unknown kind %q: use %q or %q", kind, eventKindLive, eventKindPlanned)
	}
}

// unambiguousEvent is the address of an id the caller did not qualify, or the refusal to pick one.
func unambiguousEvent(node *core.Node, path, eventID string, live, planned bool) (eventAddress, error) {
	switch {
	case live && planned:
		return eventAddress{}, apiErrorf(http.StatusConflict,
			"%q is both a live event and a plan on this node: say which with kind=%s or kind=%s",
			eventID, eventKindLive, eventKindPlanned)
	case live:
		return eventAddress{path: path, eventID: eventID, kind: eventKindLive}, nil
	case planned:
		return eventAddress{path: path, eventID: eventID, planned: true, kind: eventKindPlanned}, nil
	default:
		return eventAddress{}, apiErrorf(http.StatusNotFound, "event not found: %s", eventID)
	}
}

// asEventError gives core's refusals the status a caller can act on: an id that is not there is a
// 404 and not a server fault, and a taken id is a conflict with what is already stored.
func asEventError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, core.ErrEventNotFound):
		return apiErrorf(http.StatusNotFound, "%v", err)
	case errors.Is(err, core.ErrEventIDTaken):
		return apiErrorf(http.StatusConflict, "%v", err)
	default:
		var carried *apiError
		if errors.As(err, &carried) {
			return err
		}
		return apiErrorf(http.StatusInternalServerError, "%v", err)
	}
}

// eventPatch is the body of PATCH /events/{id}.
//
// Every field is a POINTER, and that is the whole difference between a patch and the upsert this
// route replaces: a nil field was not sent and is not changed, while a field carrying the empty
// string was sent and clears what it names. A plain string cannot tell those apart, which is
// exactly how POST /events/plan came to erase metadata nobody asked it to touch.
type eventPatch struct {
	EventID   *string                `json:"event_id"`
	StartTime *string                `json:"start_time"`
	EndTime   *string                `json:"end_time"`
	Category  *string                `json:"category"`
	Frequency *string                `json:"frequency"`
	Pattern   *string                `json:"pattern"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// applyTo merges the patch into a stored event.
func (p eventPatch) applyTo(event *core.Event, planned bool, userID string) error {
	if err := p.retime(event, planned); err != nil {
		return err
	}

	setString(&event.Category, p.Category)
	setString(&event.Frequency, p.Frequency)
	setString(&event.Pattern, p.Pattern)
	p.mergeMetadata(event)

	event.ModifiedBy = userID
	event.ModifiedAt = time.Now()
	return nil
}

// retime moves the event's ends, and refuses the one move that would be a status change in
// disguise.
func (p eventPatch) retime(event *core.Event, planned bool) error {
	start, err := parsedStamp("start_time", p.StartTime)
	if err != nil {
		return err
	}
	end, err := parsedStamp("end_time", p.EndTime)
	if err != nil {
		return err
	}

	if end != nil && !planned && event.Status != core.EventFinished {
		return apiErrorf(http.StatusConflict,
			"this event is live and %s: use POST /events/end to end it, not end_time", event.Status)
	}

	if start != nil {
		event.StartTime = start
	}
	if end != nil {
		event.EndTime = end
	}
	if event.StartTime != nil && event.EndTime != nil && event.EndTime.Before(*event.StartTime) {
		return apiErrorf(http.StatusBadRequest, "end_time is before start_time")
	}
	return nil
}

// mergeMetadata folds the patch's metadata into the event's, a key set to null DELETING it.
//
// The same rule PATCH /nodes/{path}/metadata follows, and deliberately the same: two surfaces
// annotate one record, and a replace means whichever saved last discarded the other's work.
func (p eventPatch) mergeMetadata(event *core.Event) {
	if p.Metadata == nil {
		return
	}
	if event.Metadata == nil {
		event.Metadata = make(map[string]interface{}, len(p.Metadata))
	}

	for key, value := range p.Metadata {
		if value == nil {
			delete(event.Metadata, key)
			continue
		}
		event.Metadata[key] = value
	}
}

// renameOn moves the event to the id the patch asked for, and reports the address it now has.
func (p eventPatch) renameOn(node *core.Node, at *eventAddress, userID string) error {
	if p.EventID == nil || *p.EventID == at.eventID {
		return nil
	}
	if !validEventID(*p.EventID) {
		return apiErrorf(http.StatusBadRequest, eventIDRequired)
	}

	if err := node.RenameEvent(at.eventID, *p.EventID, at.planned, userID); err != nil {
		return asEventError(err)
	}
	at.eventID = *p.EventID
	return nil
}

// parsedStamp reads an optional RFC3339 time. Absent stays absent.
func parsedStamp(field string, raw *string) (*time.Time, error) {
	if raw == nil {
		return nil, nil
	}

	parsed, err := time.Parse(time.RFC3339, *raw)
	if err != nil {
		return nil, apiErrorf(http.StatusBadRequest, "Invalid %s format", field)
	}
	return &parsed, nil
}

// setString applies an optional string field.
func setString(into *string, value *string) {
	if value != nil {
		*into = *value
	}
}
