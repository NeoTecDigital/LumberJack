// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"bytes"
	"net/http/httptest"
	"os"
	"testing"
)

func TestFeedHandlerActorAndPatchValidation(t *testing.T) {
	s, user := feedTestServer(t)
	rec := httptest.NewRecorder()
	s.HandleFeed(rec, httptest.NewRequest("GET", "/feed", nil))
	if rec.Code != 401 {
		t.Fatal("missing verified actor accepted")
	}
	rec = httptest.NewRecorder()
	s.HandleFeed(rec, withUser(httptest.NewRequest("PATCH", "/feed", bytes.NewBufferString(`{"id":"x","actor":"other","read":true}`)), user))
	if rec.Code != 400 {
		t.Fatal("actor override/unknown field accepted")
	}
	rec = httptest.NewRecorder()
	s.HandleFeed(rec, withUser(httptest.NewRequest("PATCH", "/feed", bytes.NewBufferString(`{"id":"x","read":true}{}`)), user))
	if rec.Code != 400 {
		t.Fatal("trailing body accepted")
	}
}
func TestUncertifiedFeedDoesNotWriteOrClaimOutcome(t *testing.T) {
	s, user := feedTestServer(t)
	// Unsupported state write, matching the existing failed-fsync harness.
	tempPath := s.statePath() + ".tmp"
	if err := os.Mkdir(tempPath, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := WorkCommand{Command: "create", Path: s.forest.Name, ClientID: "unknown", Title: "Goal", Kind: "goal"}
	if _, err := s.ApplyWorkCommand(user, cmd); err == nil {
		t.Fatal("failed fsync acknowledged")
	}
	before := s.stateSeq
	if raw, err := s.Feed(user); err == nil || raw != nil {
		t.Fatal("unconfirmed success projected")
	}
	if s.stateSeq != before {
		t.Fatal("feed read attempted mutation/persist retry")
	}
	attempts := s.forest.Correspondence.Feed.Attempts[user]
	for _, attempt := range attempts {
		if attempt.Outcome == "failure" {
			t.Fatal("fsync ambiguity fabricated failed outcome")
		}
	}
	if _, err := s.SweepReminders(); err == nil {
		t.Fatal("scheduler wrote uncertified state")
	}
}
