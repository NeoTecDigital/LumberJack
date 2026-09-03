package core

import (
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"time"
)

// The content a time-tracking entry carries. These are SENTINELS, not prose: GetTimeTrackingSummary
// pairs a start with a stop by matching on them exactly, so the writer and the reader have to name
// the same thing. They disagreed ("stop_time_entry" written, "end_time_entry" read), which meant a
// summary could never pair anything and time tracking reported nothing at all.
const (
	TimeEntryStart = "start_time_entry"
	TimeEntryStop  = "stop_time_entry"
)

// idSequence disambiguates two ids minted in the same nanosecond, which creating a path of nodes
// in one pass routinely does.
var idSequence atomic.Uint64

// generateID builds a unique identifier under a prefix naming what kind of thing it identifies.
func generateID(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), idSequence.Add(1))
}

// GenerateUserID generates a unique ID for a user.
func GenerateUserID() string {
	return generateID("user")
}

// GenerateNodeID generates a unique ID for a node. Nodes used to be minted by the user generator,
// so every node in the forest carried a "user-" prefix.
func GenerateNodeID() string {
	return generateID("node")
}

// GenerateEntryID generates a unique ID for an entry.
//
// EVERY entry gets one, wherever it is written from — an event append, a time-tracking sentinel or
// the activity log — because a route that addresses an entry by id must be able to address any
// entry, and an entry with no id is one no client can name.
func GenerateEntryID() string {
	return generateID("entry")
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

	now := time.Now()
	entry := Entry{
		ID:         GenerateEntryID(),
		Timestamp:  now,
		Content:    content,
		Metadata:   metadata,
		UserID:     userID,
		CreatedBy:  userID,
		CreatedAt:  now,
		ModifiedBy: userID,
		ModifiedAt: now,
	}

	event.Entries = append(event.Entries, entry)
	event.ModifiedBy = userID
	event.ModifiedAt = entry.Timestamp
	n.Events[eventID] = event
	return nil
}

// ErrEventAlreadyStarted is what a plan over a live id is refused with. A SENTINEL, so the route
// can answer 409 Conflict for it: the caller asked for something this node cannot mean, rather than
// something the server failed to do.
var ErrEventAlreadyStarted = errors.New("event has already started")

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

	// A PLAN FOR AN EVENT THAT HAS ALREADY STARTED IS NOT A PLAN. This was an unconditional upsert,
	// so planning over a live id answered success and wrote into PlannedEvents — where every
	// reader that flattens the two maps drops it, because one id is one event and the live one
	// wins. The write was accepted and then invisible to /events and /query, which is a success
	// reported for something the caller can never see again.
	//
	// Re-planning something that is still only a PLAN is untouched: moving a meeting is the whole
	// point of the route.
	if _, started := n.Events[eventID]; started {
		return fmt.Errorf("%w: %s", ErrEventAlreadyStarted, eventID)
	}

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
		ID:        GenerateEntryID(),
		Timestamp: time.Now(),
		UserID:    userID,
		Content:   TimeEntryStart,
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
		ID:        GenerateEntryID(),
		Timestamp: time.Now(),
		UserID:    userID,
		Content:   TimeEntryStop,
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

	differences := eventDifferences(plannedEvent, actualEvent)
	if len(differences) > 0 {
		return false, fmt.Errorf("differences found: %v", differences)
	}
	return true, nil
}

// eventDifferences lists every way a plan and what happened disagree.
func eventDifferences(planned, actual Event) []string {
	var differences []string

	differences = append(differences, spanDifference("StartTime", planned.StartTime, actual.StartTime)...)
	differences = append(differences, spanDifference("EndTime", planned.EndTime, actual.EndTime)...)

	if planned.Status != actual.Status {
		differences = append(differences, fmt.Sprintf("Status differs: planned=%s, actual=%s", planned.Status, actual.Status))
	}
	if !reflect.DeepEqual(planned.Metadata, actual.Metadata) {
		differences = append(differences, "Metadata differs")
	}
	return append(differences, entryDifferences(planned.Entries, actual.Entries)...)
}

// spanDifference compares one end of a span. An end that is set on one side and not the other is a
// difference in its own right, and there is no value to report for the side that has none.
func spanDifference(name string, planned, actual *time.Time) []string {
	switch {
	case planned == nil && actual == nil:
		return nil
	case planned == nil || actual == nil:
		return []string{name + " differs"}
	case !planned.Equal(*actual):
		return []string{fmt.Sprintf("%s differs: planned=%v, actual=%v", name, *planned, *actual)}
	default:
		return nil
	}
}

// entryDifferences compares the entries. A different COUNT is reported as itself rather than as a
// list of positions, because past the shorter of the two there is nothing to compare against.
func entryDifferences(planned, actual []Entry) []string {
	if len(planned) != len(actual) {
		return []string{fmt.Sprintf("Entries count differs: planned=%d, actual=%d", len(planned), len(actual))}
	}

	var differences []string
	for index := range planned {
		if !reflect.DeepEqual(planned[index], actual[index]) {
			differences = append(differences, fmt.Sprintf("Entry %d differs", index))
		}
	}
	return differences
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
	// Stamped BEFORE the copy goes into the map. These two lines used to run AFTER it, so the
	// stored attachment kept whatever the caller had put in those fields and only the caller's own
	// copy — the one echoed back in the receipt — carried the uploader and the time: the receipt
	// and the stored file could disagree about who uploaded it. The uploader is the authenticated
	// caller and is written unconditionally, so it cannot be supplied from outside.
	attachment.UploadedBy = userID
	if attachment.UploadedAt.IsZero() {
		attachment.UploadedAt = time.Now()
	}
	n.Attachments[attachment.ID] = *attachment
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

// DeleteAttachment lives in attachment_locate.go, with the lookup it has to agree with. It used to
// be here and it searched the node's own map alone, so it could not remove — or even find — a file
// that had been attached to an entry.
