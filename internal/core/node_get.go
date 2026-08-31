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
// GetNode retrieves a node by its ID
func (n *Node) GetNode(nodeID string) (*Node, error) {
	if n.ID == nodeID {
		return n, nil
	}

	if nodeID == "forest" {
		return n, nil
	}

	for _, child := range n.Children {
		if node, err := child.GetNode(nodeID); err == nil {
			return node, nil
		}
	}

	return nil, fmt.Errorf("node not found: %s", nodeID)
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

// GetTimeTrackingSummary returns a summary of the time tracking for the node
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
