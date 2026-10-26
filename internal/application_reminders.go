// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"sort"
	"time"
)

// The revision is the real stored event shape, not a manufactured event version.
func reminderRevision(event core.Event) string {
	raw, _ := json.Marshal(event)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
func reminderOccurrence(node *core.Node, path, id string, event core.Event) core.ReminderOccurrence {
	start := event.StartTime.UTC().Format(time.RFC3339Nano)
	revision := reminderRevision(event)
	raw, _ := json.Marshal([]string{node.ID, id, start, revision})
	return core.ReminderOccurrence{ID: fmt.Sprintf("%x", sha256.Sum256(raw)), NodeID: node.ID, Path: path, EventID: id, Start: start, Revision: revision}
}
func pendingReminder(node *core.Node, id string, event core.Event, now time.Time) bool {
	if node.Metadata["reminders_disabled"] == true || event.Metadata["reminders_disabled"] == true {
		return false
	}
	_, started := node.Events[id]
	return !started && event.Status == core.EventPending && event.StartTime != nil && !event.StartTime.After(now)
}

// Defaults are absence-only. Explicit false always remains authoritative.
func (s *Server) defaultWorkSubscriptions(node *core.Node, users ...string) {
	if s.forest.Subscriptions == nil {
		s.forest.Subscriptions = map[string]map[string]bool{}
	}
	for _, user := range users {
		s.defaultWorkSubscriber(node, user)
	}
}
func (s *Server) defaultWorkSubscriber(node *core.Node, user string) {
	if user == "" || user == SystemUserID || !node.CheckPermission(user, core.ReadPermission) {
		return
	}
	if s.forest.Subscriptions[user] == nil {
		s.forest.Subscriptions[user] = map[string]bool{}
	}
	if _, present := s.forest.Subscriptions[user][node.ID]; !present {
		s.forest.Subscriptions[user][node.ID] = true
	}
}
func (s *Server) reminderRecipients(node *core.Node) []string {
	recipients := []string{}
	for _, user := range s.forest.Users {
		if user.ID != SystemUserID && node.CheckPermission(user.ID, core.ReadPermission) && s.forest.Subscriptions[user.ID][node.ID] {
			recipients = append(recipients, user.ID)
		}
	}
	sort.Strings(recipients)
	return recipients
}

// SweepReminders is backend-owned due delivery; no browser timer or recurrence.
// changeForest gives local snapshot durability, NOT distributed consensus.
func (s *Server) SweepReminders() ([]byte, error) { return s.sweepRemindersAt(time.Now().UTC()) }
func (s *Server) sweepRemindersAt(now time.Time) ([]byte, error) {
	count := 0
	needed := false
	durable := false
	s.readForest(func() { durable = s.feedSnapshotDurable(); needed = s.hasDueReminder(now) })
	if !durable {
		return nil, apiErrorf(503, "Reminder snapshot durability unresolved")
	}
	if !needed {
		return json.Marshal(map[string]int{"delivered": 0})
	}
	err := s.changeForest(func() error {
		if !s.feedSnapshotDurable() {
			return apiErrorf(503, "Reminder snapshot durability unresolved")
		}
		return s.walkScope("", nil, func(at visit) { count += s.deliverNodeReminders(at.node, at.path, now) })
	})
	if err != nil {
		return nil, err
	}
	if count > 0 {
		s.publish(mutation("notification_delivered", ""))
	}
	return json.Marshal(map[string]int{"delivered": count})
}
func (s *Server) hasDueReminder(now time.Time) bool {
	found := false
	_ = s.walkScope("", nil, func(at visit) {
		if s.nodeHasDueReminder(at.node, at.path, now) {
			found = true
		}
	})
	return found
}
func (s *Server) nodeHasDueReminder(node *core.Node, path string, now time.Time) bool {
	for id, event := range node.PlannedEvents {
		if s.reminderDue(node, path, id, event, now) {
			return true
		}
	}
	return false
}
func (s *Server) reminderDue(node *core.Node, path, id string, event core.Event, now time.Time) bool {
	if !pendingReminder(node, id, event, now) {
		return false
	}
	occurrence := reminderOccurrence(node, path, id, event)
	state := s.forest.Correspondence
	if state == nil || state.Feed == nil {
		return true
	}
	_, seen := state.Feed.Reminders[occurrence.ID]
	return !seen
}
func (s *Server) deliverNodeReminders(node *core.Node, path string, now time.Time) int {
	count := 0
	for id, event := range node.PlannedEvents {
		if s.reminderDue(node, path, id, event, now) {
			count += s.deliverReminder(node, path, id, event, now)
		}
	}
	return count
}
func (s *Server) deliverReminder(node *core.Node, path, id string, event core.Event, now time.Time) int {
	s.defaultWorkSubscriptions(node, node.CreatedBy, event.CreatedBy, event.AssignedTo)
	occurrence := reminderOccurrence(node, path, id, event)
	occurrence.DeliveredAt = now.UTC().Format(time.RFC3339Nano)
	occurrence.Recipients = s.reminderRecipients(node)
	s.feedState().Reminders[occurrence.ID] = occurrence
	return len(occurrence.Recipients)
}
