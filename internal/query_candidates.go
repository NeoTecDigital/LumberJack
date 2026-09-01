package internal

import (
	"fmt"
	"sort"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// Flattening a node, an event, an entry and a time span into the one record everything downstream
// reads. This is the only file that knows the shape of the forest; the predicate, the sort, the
// page and the aggregator all see candidates.

// nodeCandidate flattens a node.
func nodeCandidate(at visit) candidate {
	node := at.node

	attachmentIDs := make([]string, 0, len(node.Attachments))
	for id := range node.Attachments {
		attachmentIDs = append(attachmentIDs, id)
	}
	sort.Strings(attachmentIDs)

	parentIDs := make([]string, 0, len(node.Parents))
	for id := range node.Parents {
		parentIDs = append(parentIDs, id)
	}
	sort.Strings(parentIDs)

	entryCount := len(node.Entries)
	for _, event := range node.Events {
		entryCount += len(event.Entries)
	}

	view := nodeSummaryView{
		ID:            node.ID,
		Path:          at.path,
		Name:          node.Name,
		Type:          nodeTypeName(node.Type),
		ParentIDs:     parentIDs,
		ChildCount:    len(node.Children),
		EventCount:    len(node.Events),
		EntryCount:    entryCount,
		Metadata:      copyMetadata(node.Metadata),
		AttachmentIDs: attachmentIDs,
		CreatedBy:     node.CreatedBy,
		CreatedAt:     node.CreatedAt,
		ModifiedBy:    node.ModifiedBy,
		ModifiedAt:    node.ModifiedAt,
	}

	return candidate{
		Kind:     selectNodes,
		NodePath: at.path,
		NodeID:   node.ID,
		ID:       node.ID,
		Index:    -1,
		UserID:   node.CreatedBy,
		Text:     []string{node.Name, at.path},
		Times: map[string]time.Time{
			timeFieldCreatedAt:  node.CreatedAt,
			timeFieldModifiedAt: node.ModifiedAt,
			timeFieldTimestamp:  node.ModifiedAt,
		},
		Metadata:  copyMetadata(node.Metadata),
		Timestamp: node.ModifiedAt,
		View:      view,
	}
}

// eventCandidates flattens a node's events AND its planned events.
//
// Planned events are events. Leaving them out is why the calendar surface had nothing to draw: a
// plan is exactly the thing a caller wants to find before it has happened.
func eventCandidates(at visit) []candidate {
	gathered := make([]candidate, 0, len(at.node.Events)+len(at.node.PlannedEvents))
	for _, eventID := range sortedEventIDs(at.node.Events) {
		gathered = append(gathered, eventCandidate(at, eventID, at.node.Events[eventID]))
	}
	for _, eventID := range sortedEventIDs(at.node.PlannedEvents) {
		if _, alsoStarted := at.node.Events[eventID]; alsoStarted {
			// The same id in both maps is ONE event that was planned and then started. Reporting it
			// twice would double every count an aggregate produced over it.
			continue
		}
		gathered = append(gathered, eventCandidate(at, eventID, at.node.PlannedEvents[eventID]))
	}
	return gathered
}

// eventCandidate flattens one event.
func eventCandidate(at visit, eventID string, event core.Event) candidate {
	view := eventResultView{
		NodePath:   at.path,
		EventID:    eventID,
		Status:     event.Status,
		Category:   event.Category,
		Frequency:  event.Frequency,
		Pattern:    event.Pattern,
		StartTime:  event.StartTime,
		EndTime:    event.EndTime,
		EntryCount: len(event.Entries),
		Metadata:   copyMetadata(event.Metadata),
		CreatedBy:  event.CreatedBy,
		CreatedAt:  event.CreatedAt,
		ModifiedBy: event.ModifiedBy,
		ModifiedAt: event.ModifiedAt,
	}

	item := candidate{
		Kind:      selectEvents,
		NodePath:  at.path,
		NodeID:    at.node.ID,
		ID:        eventID,
		Index:     -1,
		Status:    string(event.Status),
		Category:  event.Category,
		UserID:    event.CreatedBy,
		Text:      []string{eventID, event.Category, at.node.Name},
		Metadata:  copyMetadata(event.Metadata),
		Timestamp: event.CreatedAt,
		Times: map[string]time.Time{
			timeFieldCreatedAt:  event.CreatedAt,
			timeFieldModifiedAt: event.ModifiedAt,
			timeFieldTimestamp:  event.CreatedAt,
		},
	}

	if event.StartTime != nil {
		item.Times[timeFieldStart] = *event.StartTime
	}
	if event.EndTime != nil {
		item.Times[timeFieldEnd] = *event.EndTime
	}

	// A duration exists only when the event has BOTH ends. An ongoing event counts, but summing
	// "now minus start" into a total would make the same query answer differently every time.
	if event.StartTime != nil && event.EndTime != nil {
		item.Duration = event.EndTime.Sub(*event.StartTime)
		item.HasDuration = true
		milliseconds := item.Duration.Milliseconds()
		view.DurationMS = &milliseconds
	}

	item.View = view
	return item
}

// entryCandidates flattens every entry on a node: the ones inside its events, and the ones recorded
// on the node itself by time tracking and the activity log.
func entryCandidates(at visit) []candidate {
	var gathered []candidate

	for _, eventID := range sortedEventIDs(at.node.Events) {
		event := at.node.Events[eventID]
		for index, entry := range event.Entries {
			gathered = append(gathered, entryCandidate(at, eventID, index, entry, event.Category, string(event.Status)))
		}
	}

	for index, entry := range at.node.Entries {
		gathered = append(gathered, entryCandidate(at, "", index, entry, "", ""))
	}
	return gathered
}

// entryCandidate flattens one entry. category and status are the containing event's, so that a
// query can select the entries of ongoing inspections without first selecting the events.
func entryCandidate(at visit, eventID string, index int, entry core.Entry, category, status string) candidate {
	view := entryResultView{
		NodePath:   at.path,
		EventID:    eventID,
		EntryIndex: index,
		Content:    entry.Content,
		Metadata:   copyMetadata(entry.Metadata),
		UserID:     entry.UserID,
		Timestamp:  entry.Timestamp,
	}
	for _, attachment := range entry.Attachments {
		view.Attachments = append(view.Attachments, newAttachmentView(attachment))
	}

	return candidate{
		Kind:      selectEntries,
		NodePath:  at.path,
		NodeID:    at.node.ID,
		ID:        eventID,
		Index:     index,
		Status:    status,
		Category:  category,
		UserID:    entry.UserID,
		Text:      []string{contentText(entry.Content), at.node.Name, eventID},
		Metadata:  copyMetadata(entry.Metadata),
		Timestamp: entry.Timestamp,
		Times: map[string]time.Time{
			timeFieldTimestamp:  entry.Timestamp,
			timeFieldCreatedAt:  entry.CreatedAt,
			timeFieldModifiedAt: entry.ModifiedAt,
		},
		View: view,
	}
}

// timeSpanCandidates pairs the node's time-tracking starts with their stops.
//
// This is what `select: "time"` aggregates over. An unmatched start is a span still running and has
// no duration, so it is not reported: a report of hours worked may not include an hour that has not
// finished elapsing.
func timeSpanCandidates(at visit) []candidate {
	var gathered []candidate
	open := map[string]*core.Entry{}

	for index := range at.node.Entries {
		entry := at.node.Entries[index]
		switch entry.Content {
		case core.TimeEntryStart:
			open[entry.UserID] = &entry
		case core.TimeEntryStop:
			started, running := open[entry.UserID]
			if !running {
				continue
			}
			delete(open, entry.UserID)
			gathered = append(gathered, timeSpanCandidate(at, index, *started, entry))
		}
	}
	return gathered
}

// timeSpanCandidate flattens one closed span.
func timeSpanCandidate(at visit, index int, started, stopped core.Entry) candidate {
	duration := stopped.Timestamp.Sub(started.Timestamp)
	milliseconds := duration.Milliseconds()

	return candidate{
		Kind:      selectTime,
		NodePath:  at.path,
		NodeID:    at.node.ID,
		ID:        fmt.Sprintf("span-%d", index),
		Index:     index,
		UserID:    started.UserID,
		Text:      []string{at.node.Name, at.path},
		Metadata:  copyMetadata(started.Metadata),
		Timestamp: started.Timestamp,
		Times: map[string]time.Time{
			timeFieldStart:     started.Timestamp,
			timeFieldEnd:       stopped.Timestamp,
			timeFieldTimestamp: started.Timestamp,
		},
		Duration:    duration,
		HasDuration: true,
		View: map[string]interface{}{
			"node_path":   at.path,
			"user_id":     started.UserID,
			"start_time":  started.Timestamp,
			"end_time":    stopped.Timestamp,
			"duration_ms": milliseconds,
		},
	}
}

// sortedEventIDs is a node's event ids in a fixed order, for the same reason childrenByName exists.
func sortedEventIDs(events map[string]core.Event) []string {
	ids := make([]string, 0, len(events))
	for id := range events {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// copyMetadata hands out a copy.
//
// The map belongs to the forest. A result that carried the live map would let a caller's JSON
// encoder read it after the read hold was released, which is the race this phase exists to close.
func copyMetadata(metadata map[string]interface{}) map[string]interface{} {
	if len(metadata) == 0 {
		return nil
	}

	copied := make(map[string]interface{}, len(metadata))
	for key, value := range metadata {
		copied[key] = value
	}
	return copied
}

// contentText renders an entry's content for a text search. Content is `interface{}`, so it is a
// string for an event entry and a sentinel for a time-tracking one.
func contentText(content interface{}) string {
	if text, ok := content.(string); ok {
		return text
	}
	return fmt.Sprintf("%v", content)
}
