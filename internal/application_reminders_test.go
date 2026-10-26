// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"context"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"testing"
	"time"
)

func feedTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	server := newServerInDirs(t, dir, dir)
	t.Cleanup(func() { server.Shutdown(context.Background()) })
	return server, adminID(t, server)
}
func dueFeedPlan(t *testing.T, s *Server, user string) {
	t.Helper()
	start, end := time.Now().Add(-time.Minute), time.Now().Add(time.Minute)
	if err := s.changeForest(func() error {
		return s.forest.PlanEvent("due", user, &start, &end, map[string]interface{}{"private": "not projected"})
	}); err != nil {
		t.Fatal(err)
	}
}
func feedPayload(t *testing.T, s *Server, user string) map[string][]map[string]interface{} {
	t.Helper()
	raw, err := s.Feed(user)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string][]map[string]interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func TestReminderOnceStoredStartAndRestartCodec(t *testing.T) {
	s, user := feedTestServer(t)
	dueFeedPlan(t, s, user)
	if _, err := s.SweepReminders(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepReminders(); err != nil {
		t.Fatal(err)
	}
	reminders := feedPayload(t, s, user)["reminders"]
	if len(reminders) != 1 {
		t.Fatalf("want one occurrence: %v", reminders)
	}
	if _, exists := reminders[0]["private"]; exists {
		t.Fatal("content copied to reminder")
	}
	raw, err := encodeState(s.forest)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodeState(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Correspondence.Feed.Reminders) != 1 {
		t.Fatal("dedup not persisted")
	}
}
func TestReminderRetimeStartAndDeleteInvalidation(t *testing.T) {
	s, user := feedTestServer(t)
	dueFeedPlan(t, s, user)
	if _, err := s.SweepReminders(); err != nil {
		t.Fatal(err)
	}
	if err := s.changeForest(func() error {
		event := s.forest.PlannedEvents["due"]
		later := time.Now().Add(time.Hour)
		event.StartTime = &later
		s.forest.PlannedEvents["due"] = event
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(feedPayload(t, s, user)["reminders"]) != 0 {
		t.Fatal("retimed stale reminder exposed")
	}
	if err := s.changeForest(func() error {
		s.forest.Events["due"] = core.Event{Status: core.EventPending}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepReminders(); err != nil {
		t.Fatal(err)
	}
	if len(s.forest.Correspondence.Feed.Reminders) != 1 {
		t.Fatal("started occurrence delivered")
	}
	if err := s.changeForest(func() error { delete(s.forest.PlannedEvents, "due"); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(feedPayload(t, s, user)["reminders"]) != 0 {
		t.Fatal("deleted reminder exposed")
	}
}
func TestReminderExplicitFalseAndAssigneeDefaults(t *testing.T) {
	s, user := feedTestServer(t)
	dueFeedPlan(t, s, user)
	if err := s.changeForest(func() error {
		s.forest.Users = append(s.forest.Users, core.User{ID: "bob", Username: "bob", Permissions: []core.Permission{core.ReadPermission}})
		event := s.forest.PlannedEvents["due"]
		event.AssignedTo = "bob"
		s.forest.PlannedEvents["due"] = event
		s.forest.Subscriptions = map[string]map[string]bool{user: {s.forest.ID: false}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepReminders(); err != nil {
		t.Fatal(err)
	}
	if len(feedPayload(t, s, user)["reminders"]) != 0 {
		t.Fatal("explicit false overridden")
	}
	if len(feedPayload(t, s, "bob")["reminders"]) != 1 {
		t.Fatal("absent assignee default missing")
	}
	if err := s.changeForest(func() error { s.forest.Subscriptions["bob"][s.forest.ID] = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(feedPayload(t, s, "bob")["reminders"]) != 0 {
		t.Fatal("unsubscribed delivery exposed")
	}
}

func TestReminderCurrentPermissionAndStartedEventRefusal(t *testing.T) {
	s, user := feedTestServer(t)
	dueFeedPlan(t, s, user)
	if err := s.changeForest(func() error {
		s.forest.Users = append(s.forest.Users, core.User{ID: "bob", Username: "bob", Permissions: []core.Permission{core.ReadPermission}})
		event := s.forest.PlannedEvents["due"]
		event.AssignedTo = "bob"
		s.forest.PlannedEvents["due"] = event
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepReminders(); err != nil {
		t.Fatal(err)
	}
	if err := s.changeForest(func() error {
		clearFeedMemberPermissions(s.forest, "bob")
		s.forest.Events["due"] = core.Event{Status: core.EventOngoing}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(feedPayload(t, s, "bob")["reminders"]) != 0 {
		t.Fatal("current ACL ignored")
	}
	if _, err := s.SweepReminders(); err != nil {
		t.Fatal(err)
	}
	if len(s.forest.Correspondence.Feed.Reminders) != 1 {
		t.Fatal("started plan delivered again")
	}
}

func clearFeedMemberPermissions(node *core.Node, user string) {
	for index, member := range node.Users {
		if member.ID == user {
			node.Users[index].Permissions = nil
		}
	}
}
