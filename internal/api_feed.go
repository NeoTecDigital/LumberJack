// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"io"
	"net/http"
	"sort"
	"time"
)

type FeedPatch struct {
	ID       string `json:"id"`
	Read     *bool  `json:"read,omitempty"`
	Archived *bool  `json:"archived,omitempty"`
}

// HandleFeed requires the actor supplied by the existing auth middleware.
// The coordinator must bind that middleware to signed-current business admission.
func (s *Server) HandleFeed(w http.ResponseWriter, r *http.Request) {
	user, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "Sign in required", 401)
		return
	}
	if r.Method != "GET" && r.Method != "PATCH" {
		http.Error(w, "Method unavailable", 405)
		return
	}
	if r.Method == "PATCH" {
		var patch FeedPatch
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&patch) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "Invalid feed update", 400)
			return
		}
		if err := s.PatchFeed(user, patch); err != nil {
			writeAPIError(w, err)
			return
		}
	}
	body, err := s.Feed(user)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// Read never retries a previously ambiguous mutation or persists state.
func (s *Server) Feed(user string) ([]byte, error) {
	var body []byte
	var failure error
	s.readForest(func() {
		if _, err := s.forest.GetUserProfile(user); err != nil {
			failure = apiErrorf(401, "Account unavailable")
			return
		}
		if !s.feedSnapshotDurable() {
			failure = apiErrorf(503, "Feed snapshot durability unresolved")
			return
		}
		alerts, reminders := s.feedViews(user)
		body, failure = json.Marshal(map[string]interface{}{"alerts": alerts, "reminders": reminders})
	})
	return body, failure
}
func (s *Server) feedViews(user string) ([]map[string]interface{}, []map[string]interface{}) {
	alerts, reminders := []map[string]interface{}{}, []map[string]interface{}{}
	state := s.forest.Correspondence
	if state == nil || state.Feed == nil {
		return alerts, reminders
	}
	feed := state.Feed
	for _, attempt := range feed.Attempts[user] {
		alerts = append(alerts, s.alertView(user, attempt, feed.Marks[user][attempt.ID]))
	}
	for _, occurrence := range feed.Reminders {
		if item := s.reminderView(user, occurrence, feed.Marks[user][occurrence.ID]); item != nil {
			reminders = append(reminders, item)
		}
	}
	sort.Slice(alerts, func(i, j int) bool { return alerts[i]["at"].(string) > alerts[j]["at"].(string) })
	sort.Slice(reminders, func(i, j int) bool { return reminders[i]["at"].(string) > reminders[j]["at"].(string) })
	return alerts, reminders
}
func (s *Server) alertView(user string, attempt core.FeedAttempt, mark core.FeedMark) map[string]interface{} {
	item := map[string]interface{}{"id": attempt.ID, "command_id": attempt.CommandID, "operation": attempt.Operation, "outcome": attempt.Outcome, "status": attempt.Status, "at": attempt.At, "read_at": mark.ReadAt, "archived_at": mark.ArchivedAt}
	if attempt.Severity != "" {
		item["severity"] = attempt.Severity
	}
	node, err := s.getNodeFromPath(attempt.Path)
	if err == nil && node.ID == attempt.NodeID && node.CheckPermission(user, core.ReadPermission) {
		item["pin_id"], item["path"] = node.ID, attempt.Path
	}
	return item
}
func (s *Server) reminderView(user string, occurrence core.ReminderOccurrence, mark core.FeedMark) map[string]interface{} {
	node, err := s.getNodeFromPath(occurrence.Path)
	if err != nil || node.ID != occurrence.NodeID || !node.CheckPermission(user, core.ReadPermission) || !s.forest.Subscriptions[user][node.ID] {
		return nil
	}
	event, exists := node.PlannedEvents[occurrence.EventID]
	if !exists || !pendingReminder(node, occurrence.EventID, event, time.Now()) || reminderRevision(event) != occurrence.Revision {
		return nil
	}
	found := false
	for _, recipient := range occurrence.Recipients {
		if recipient == user {
			found = true
		}
	}
	if !found {
		return nil
	}
	return map[string]interface{}{"id": occurrence.ID, "pin_id": node.ID, "path": occurrence.Path, "event_id": occurrence.EventID, "start": occurrence.Start, "revision": occurrence.Revision, "operation": "reminder_due", "at": occurrence.DeliveredAt, "read_at": mark.ReadAt, "archived_at": mark.ArchivedAt}
}
func (s *Server) PatchFeed(user string, patch FeedPatch) error {
	if patch.ID == "" || len(patch.ID) > 128 || (patch.Read == nil && patch.Archived == nil) {
		return apiErrorf(400, "Choose a feed item and state")
	}
	err := s.changeForest(func() error {
		if !s.feedSnapshotDurable() {
			return apiErrorf(503, "Feed snapshot durability unresolved")
		}
		if _, err := s.forest.GetUserProfile(user); err != nil {
			return apiErrorf(401, "Account unavailable")
		}
		if !s.ownsFeedItem(user, patch.ID) {
			return apiErrorf(404, "Feed item unavailable")
		}
		feed := s.feedState()
		if feed.Marks[user] == nil {
			feed.Marks[user] = map[string]core.FeedMark{}
		}
		mark := feed.Marks[user][patch.ID]
		mark.ReadAt = feedMarkTime(mark.ReadAt, patch.Read)
		mark.ArchivedAt = feedMarkTime(mark.ArchivedAt, patch.Archived)
		feed.Marks[user][patch.ID] = mark
		return nil
	})
	if err == nil {
		s.publish(mutation("feed_read", ""))
	}
	return err
}
func feedMarkTime(current string, value *bool) string {
	if value == nil {
		return current
	}
	if !*value {
		return ""
	}
	if current != "" {
		return current
	}
	return time.Now().UTC().Format(time.RFC3339Nano)
}
func (s *Server) ownsFeedItem(user, id string) bool {
	state := s.forest.Correspondence
	if state == nil || state.Feed == nil {
		return false
	}
	for _, attempt := range state.Feed.Attempts[user] {
		if attempt.ID == id {
			return true
		}
	}
	if occurrence, exists := state.Feed.Reminders[id]; exists {
		return s.reminderView(user, occurrence, core.FeedMark{}) != nil
	}
	return false
}
