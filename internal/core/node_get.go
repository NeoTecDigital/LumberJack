package core

import (
	"fmt"
	"time"
)

// GetPlannedEvents returns all planned events
func (n *Node) GetPlannedEvents() (map[string]Event, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	plannedEvents := make(map[string]Event)
	for k, v := range n.PlannedEvents {
		plannedEvents[k] = v
	}
	return plannedEvents, nil
}

// TODO: Allow it to search for nodes by name or ID
// GetNode retrieves a node by its ID.
//
// The forest is a MULTI-PARENT DAG, so this carries a visit set: a node reachable by two paths is
// searched once, and an edge that closes a loop terminates instead of recursing until the stack
// runs out. It used to recurse down Children unguarded, which took the process down.
func (n *Node) GetNode(nodeID string) (*Node, error) {
	if node := n.findNode(nodeID, map[string]bool{}); node != nil {
		return node, nil
	}
	return nil, fmt.Errorf("node not found: %s", nodeID)
}

// findNode is GetNode carrying the set of nodes already searched.
func (n *Node) findNode(nodeID string, visited map[string]bool) *Node {
	if n.ID == nodeID || nodeID == "forest" {
		return n
	}
	if visited[n.ID] {
		return nil
	}
	visited[n.ID] = true

	for _, child := range n.Children {
		if node := child.findNode(nodeID, visited); node != nil {
			return node
		}
	}
	return nil
}

// GetEventSummary returns a summary of the event's current status
func (n *Node) GetEventSummary(eventID string) (*EventSummary, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	event, exists := n.Events[eventID]
	if !exists {
		return nil, fmt.Errorf("event not found: %s", eventID)
	}

	summary := &EventSummary{
		Status:       event.Status,
		EntriesCount: len(event.Entries),
	}

	now := time.Now()
	if event.EndTime != nil {
		summary.Status = EventFinished
		duration := event.EndTime.Sub(*event.StartTime).String()
		summary.Duration = &duration
	} else if event.StartTime != nil {
		summary.Status = EventOngoing
		duration := now.Sub(*event.StartTime).String()
		summary.Duration = &duration
	} else if event.Status == EventPending {
		summary.Status = EventPending
	}

	if len(event.Entries) > 0 {
		lastEntry := event.Entries[len(event.Entries)-1]
		summary.LastUpdateTime = &lastEntry.Timestamp
	}

	return summary, nil
}

// GetAllEventEntries returns all entries for all events
func (n *Node) GetAllEventEntries() ([]Entry, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	var allEntries []Entry
	for _, event := range n.Events {
		allEntries = append(allEntries, event.Entries...)
	}
	return allEntries, nil
}

// GetEventEntries returns all entries for an event
func (n *Node) GetEventEntries(eventID string) ([]Entry, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	event, exists := n.Events[eventID]
	if !exists {
		return nil, fmt.Errorf("event not found: %s", eventID)
	}

	entries := make([]Entry, len(event.Entries))
	copy(entries, event.Entries)
	return entries, nil
}

// GetTimeTrackingSummary returns a summary of the time tracking for the node.
//
// UNITS: "duration" is a time.Duration, which encodes as an integer count of NANOSECONDS. It is
// what GET /time and POST /time/stop answer with and it is unchanged. The same quantity appears as
// MILLISECONDS (`duration_ms`) on a /query time result and as SECONDS (`duration_sum`) on an
// /aggregate bucket — three units for one thing, each named where it is returned.
func (n *Node) GetTimeTrackingSummary(userID string) []map[string]interface{} {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	var summary []map[string]interface{}

	var startTime *Entry
	for _, entry := range n.Entries {
		if entry.UserID == userID {
			if entry.Content == TimeEntryStart {
				startTime = &entry
			} else if entry.Content == TimeEntryStop && startTime != nil {
				duration := entry.Timestamp.Sub(startTime.Timestamp)
				summary = append(summary, map[string]interface{}{
					// A SPAN IS NAMED BY THE ENTRY THAT OPENS IT. A span is not stored — it is two
					// entries read as a pair — so it has no identity of its own to carry, and the
					// start's id is the only name for it that survives an entry being inserted
					// before it. DELETE /time/{id} takes exactly this id.
					"id":         startTime.ID,
					"start_time": startTime.Timestamp,
					"end_time":   entry.Timestamp,
					"duration":   duration,
				})
				startTime = nil // Reset startTime for the next event
			}
		}
	}

	return summary
}

// GetUserProfile returns the user profile
func (n *Node) GetUserProfile(userID string) (*User, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	var user *User

	for _, u := range n.Users {
		if u.ID == userID {
			user = &u
			break
		}
	}

	if user == nil {
		return nil, fmt.Errorf("user not found: %s", userID)
	}
	return user, nil
}
