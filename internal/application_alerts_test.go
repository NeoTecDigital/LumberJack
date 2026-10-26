// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"fmt"
	"testing"
)

func TestFeedSuccessReceiptConflictDoesNotOverwrite(t *testing.T) {
	s, user := feedTestServer(t)
	cmd := WorkCommand{Command: "create", Path: s.forest.Name, ClientID: "stable", Title: "Goal", Kind: "goal"}
	original, err := s.ApplyWorkCommand(user, cmd)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Title = "Changed"
	if _, err := s.ApplyWorkCommand(user, cmd); err == nil {
		t.Fatal("changed digest accepted")
	}
	receipt := s.forest.Correspondence.Feed.Receipts[feedIdentity(user, cmd.ClientID)]
	if receipt.Status != 200 || string(receipt.Result) != string(original) {
		t.Fatal("failure overwrote success receipt")
	}
	cmd.Title = "Goal"
	replay, err := s.ApplyWorkCommand(user, cmd)
	if err != nil || string(replay) != string(original) {
		t.Fatalf("stable replay: %v", err)
	}
	alerts := feedPayload(t, s, user)["alerts"]
	if len(alerts) != 2 {
		t.Fatalf("immutable attempts missing: %v", alerts)
	}
}
func TestAlertsRetentionAndSeparateReadArchiveMarks(t *testing.T) {
	s, user := feedTestServer(t)
	if err := s.changeForest(func() error {
		for i := 0; i < 205; i++ {
			s.appendFeedAttempt(user, WorkCommand{ClientID: fmt.Sprint(i), Command: "log"}, "digest", s.forest.ID, s.forest.Name, "success", 200)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	alerts := feedPayload(t, s, user)["alerts"]
	if len(alerts) != 205 {
		t.Fatal("alerts truncated to capped notification inbox")
	}
	id := alerts[0]["id"].(string)
	yes := true
	if err := s.PatchFeed(user, FeedPatch{ID: id, Read: &yes, Archived: &yes}); err != nil {
		t.Fatal(err)
	}
	attempts := s.forest.Correspondence.Feed.Attempts[user]
	if len(attempts) != 205 {
		t.Fatal("mark mutated immutable history")
	}
	mark := s.forest.Correspondence.Feed.Marks[user][id]
	if mark.ReadAt == "" || mark.ArchivedAt == "" {
		t.Fatal("read/archive marks missing")
	}
	no := false
	if err := s.PatchFeed(user, FeedPatch{ID: id, Archived: &no}); err != nil {
		t.Fatal(err)
	}
	if s.forest.Correspondence.Feed.Marks[user][id].ReadAt != mark.ReadAt {
		t.Fatal("archive changed read evidence")
	}
}
func TestAlertReferenceRedactionAfterNodeLoss(t *testing.T) {
	s, user := feedTestServer(t)
	if err := s.changeForest(func() error {
		s.appendFeedAttempt(user, WorkCommand{ClientID: "lost", Command: "log"}, "digest", "missing", "missing/path", "success", 200)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	alerts := feedPayload(t, s, user)["alerts"]
	if len(alerts) != 1 || alerts[0]["outcome"] != "success" {
		t.Fatal("private outcome history removed")
	}
	if _, exists := alerts[0]["path"]; exists {
		t.Fatal("lost resource reference leaked")
	}
}
