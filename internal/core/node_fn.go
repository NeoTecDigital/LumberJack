package core

import (
	"fmt"
	"reflect"
	"time"
)

// GenerateID generates a unique ID for a user
func GenerateID() string {
	return fmt.Sprintf("user-%d", time.Now().UnixNano())
}

// StartEvent starts a new event or schedules it for the future
func (n *Node) StartEvent(eventID string, userID string, plannedStart, plannedEnd *time.Time, metadata map[string]interface{}) error {
	if n.Type != LeafNode {
		return fmt.Errorf("cannot add event to non-leaf node")
	}

	// Check user permission
	if !n.CheckPermission(userID, WritePermission) {
		return fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	event := Event{
		Metadata:   metadata,
		Status:     EventPending,
		CreatedBy:  userID,
		CreatedAt:  time.Now(),
		ModifiedBy: userID,
		ModifiedAt: time.Now(),
	}

	// Handle category if provided in metadata
	if category, ok := metadata["category"].(string); ok {
		event.Category = category
	}

	// Handle frequency if provided in metadata
	if frequency, ok := metadata["frequency"].(string); ok {
		event.Frequency = frequency
	}

	// Handle custom pattern if provided in metadata
	if pattern, ok := metadata["custom_pattern"].(string); ok {
		event.Pattern = pattern
	}

	if plannedStart == nil || time.Now().After(*plannedStart) {
		now := time.Now()
		event.StartTime = &now
		event.Status = EventOngoing
	}

	n.Events[eventID] = event
	return nil
}

// EndEvent marks an event as finished
func (n *Node) EndEvent(eventID string, userID string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Check user permission
	if !n.CheckPermission(userID, WritePermission) {
		return fmt.Errorf("insufficient permissions")
	}

	event, exists := n.Events[eventID]
	if !exists {
		return fmt.Errorf("event not found: %s", eventID)
	}

	if event.StartTime == nil {
		return fmt.Errorf("cannot end event that hasn't started")
	}

	now := time.Now()
	event.EndTime = &now
	event.Status = EventFinished
	event.ModifiedBy = userID
	event.ModifiedAt = now
	n.Events[eventID] = event
	return nil
}

// AppendToEvent adds a new entry to an ongoing event
func (n *Node) AppendToEvent(eventID string, userID string, content interface{}, metadata map[string]interface{}) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Check user permission
	if !n.CheckPermission(userID, WritePermission) {
		return fmt.Errorf("insufficient permissions")
	}

	event, exists := n.Events[eventID]
	if !exists {
		return fmt.Errorf("event not found: %s", eventID)
	}

	if event.EndTime != nil {
		return fmt.Errorf("cannot append to finished event")
	}

	if event.StartTime == nil {
		return fmt.Errorf("cannot append to event that hasn't started")
	}

	entry := Entry{
		Timestamp: time.Now(),
		Content:   content,
		Metadata:  metadata,
		UserID:    userID,
	}

	event.Entries = append(event.Entries, entry)
	event.ModifiedBy = userID
	event.ModifiedAt = entry.Timestamp
	n.Events[eventID] = event
	return nil
}

// PlanEvent plans a future event
func (n *Node) PlanEvent(eventID string, userID string, plannedStart, plannedEnd *time.Time, metadata map[string]interface{}) error {
	if n.Type != LeafNode {
		return fmt.Errorf("cannot plan event for non-leaf node")
	}

	// Check user permission
	if !n.CheckPermission(userID, WritePermission) {
		return fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	event := Event{
		Metadata:  metadata,
		Status:    EventPending,
		CreatedBy: userID,
		CreatedAt: time.Now(),
		StartTime: plannedStart,
		EndTime:   plannedEnd,
	}

	n.PlannedEvents[eventID] = event
	return nil
}

// CheckPermission checks if a user has permission to perform an action on the node.
//
// Permissions are ranked, not matched exactly: Read < Write < Admin, which is the order the
// constants are declared in. An admin who had to be granted WritePermission separately to append
// to an event is an admin in name only, and every event route asks for WritePermission.
func (n *Node) CheckPermission(userID string, permission Permission) bool {
	for _, user := range n.Users {
		if user.ID == userID {
			for _, perm := range user.Permissions {

				if perm >= permission {
					return true
				}
			}
		}
	}
	return false
}

// TODO: Ensure user calling this function has admin permissions to this node
// AssignUser assigns a user to the node with permission checking
func (n *Node) AssignUser(user User, permission Permission) error {
	// Add user to node's Users slice if not already present
	found := false
	for i := range n.Users {
		if n.Users[i].ID == user.ID {
			found = true
			n.Users[i].Permissions = append(n.Users[i].Permissions, permission)
			break
		}
	}
	if !found {
		// The permission is ADDED to whatever the user already carries rather than replacing it,
		// which is what the branch above does for a user the node already knows.
		user.Permissions = append(user.Permissions, permission)
		n.Users = append(n.Users, user)
	}
	return nil
}

func (n *Node) StartTimeTracking(userID string) (*Entry, error) {
	// Check user permission
	if !n.CheckPermission(userID, WritePermission) {
		return nil, fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	entry := Entry{
		Timestamp: time.Now(),
		UserID:    userID,
		Content:   "start_time_entry",
	}

	n.Entries = append(n.Entries, entry)
	return &entry, nil
}

// StopTimeTracking stops tracking time for the node
func (n *Node) StopTimeTracking(userID string) (*Entry, error) {
	// Check user permission
	if !n.CheckPermission(userID, WritePermission) {
		return nil, fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	entry := Entry{
		Timestamp: time.Now(),
		UserID:    userID,
		Content:   "stop_time_entry",
	}

	n.Entries = append(n.Entries, entry)
	return &entry, nil
}

// CompareEvents compares the planned event to the actual event and reports differences
func (n *Node) CompareEvents(plannedEventID, actualEventID string) (bool, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	plannedEvent, plannedExists := n.PlannedEvents[plannedEventID]
	actualEvent, actualExists := n.Events[actualEventID]

	if !plannedExists || !actualExists {
		return false, fmt.Errorf("one or both events not found: plannedEventID=%s, actualEventID=%s", plannedEventID, actualEventID)
	}

	// Initialize a slice to hold differences
	var differences []string

	// Compare StartTime
	if (plannedEvent.StartTime == nil && actualEvent.StartTime != nil) || (plannedEvent.StartTime != nil && actualEvent.StartTime == nil) {
		differences = append(differences, "StartTime differs")
	} else if plannedEvent.StartTime != nil && actualEvent.StartTime != nil && !plannedEvent.StartTime.Equal(*actualEvent.StartTime) {
		differences = append(differences, fmt.Sprintf("StartTime differs: planned=%v, actual=%v", *plannedEvent.StartTime, *actualEvent.StartTime))
	}

	// Compare EndTime
	if (plannedEvent.EndTime == nil && actualEvent.EndTime != nil) || (plannedEvent.EndTime != nil && actualEvent.EndTime == nil) {
		differences = append(differences, "EndTime differs")
	} else if plannedEvent.EndTime != nil && actualEvent.EndTime != nil && !plannedEvent.EndTime.Equal(*actualEvent.EndTime) {
		differences = append(differences, fmt.Sprintf("EndTime differs: planned=%v, actual=%v", *plannedEvent.EndTime, *actualEvent.EndTime))
	}

	// Compare Status
	if plannedEvent.Status != actualEvent.Status {
		differences = append(differences, fmt.Sprintf("Status differs: planned=%s, actual=%s", plannedEvent.Status, actualEvent.Status))
	}

	// Compare Metadata
	if !reflect.DeepEqual(plannedEvent.Metadata, actualEvent.Metadata) {
		differences = append(differences, "Metadata differs")
	}

	// Compare Entries
	if len(plannedEvent.Entries) != len(actualEvent.Entries) {
		differences = append(differences, fmt.Sprintf("Entries count differs: planned=%d, actual=%d", len(plannedEvent.Entries), len(actualEvent.Entries)))
	} else {
		for i := range plannedEvent.Entries {
			if !reflect.DeepEqual(plannedEvent.Entries[i], actualEvent.Entries[i]) {
				differences = append(differences, fmt.Sprintf("Entry %d differs", i))
			}
		}
	}

	// If there are differences, return them
	if len(differences) > 0 {
		return false, fmt.Errorf("differences found: %v", differences)
	}

	return true, nil
}

// Add attachment to node
func (n *Node) AddAttachment(attachment *Attachment, userID string) error {
	if !n.CheckPermission(userID, WritePermission) {
		return fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.Attachments == nil {
		n.Attachments = make(map[string]Attachment)
	}
	n.Attachments[attachment.ID] = *attachment
	attachment.UploadedBy = userID
	attachment.UploadedAt = time.Now()
	return nil
}

// Add attachment to entry
func (n *Node) AddEntryAttachment(eventID string, entryIndex int, attachment *Attachment, userID string) error {
	if !n.CheckPermission(userID, WritePermission) {
		return fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	event, exists := n.Events[eventID]
	if !exists {
		return fmt.Errorf("event not found: %s", eventID)
	}

	if entryIndex < 0 || entryIndex >= len(event.Entries) {
		return fmt.Errorf("invalid entry index: %d", entryIndex)
	}

	event.Entries[entryIndex].Attachments = append(event.Entries[entryIndex].Attachments, *attachment)
	n.Events[eventID] = event
	return nil
}

// DeleteAttachment removes an attachment from a node
func (n *Node) DeleteAttachment(attachmentID string, userID string) error {
	if !n.CheckPermission(userID, WritePermission) {
		return fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.Attachments == nil {
		return fmt.Errorf("attachment not found: %s", attachmentID)
	}

	if _, exists := n.Attachments[attachmentID]; !exists {
		return fmt.Errorf("attachment not found: %s", attachmentID)
	}

	delete(n.Attachments, attachmentID)
	return nil
}
