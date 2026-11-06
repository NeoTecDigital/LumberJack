package internal

import (
	"bytes"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"net/http/httptest"
	"testing"
)

func TestGlobalFeedPreferencesCASAndReadDefaults(t *testing.T) {
	s, user := feedTestServer(t)
	before := s.stateSeq
	p, e := s.FeedPreferences(user)
	if e != nil || p.Revision != 0 || !p.InApp.Enabled || !p.InApp.Reminders {
		t.Fatalf("defaults %+v %v", p, e)
	}
	if s.stateSeq != before {
		t.Fatal("GET mutated state")
	}
	rev := uint64(0)
	disabled := false
	patch := FeedPreferencesPatch{ExpectedRevision: &rev, InApp: FeedChannelsPatch{Reminders: &disabled}}
	if e = s.PatchFeedPreferences(user, patch); e != nil {
		t.Fatal(e)
	}
	p, e = s.FeedPreferences(user)
	if e != nil || p.Revision != 1 || p.InApp.Reminders || !p.InApp.Notifications {
		t.Fatalf("patch %+v %v", p, e)
	}
	if e = s.PatchFeedPreferences(user, patch); e == nil {
		t.Fatal("stale revision accepted")
	}
	s.readForest(func() {
		if s.notificationDeliveryEnabled(user, "reminder_due") || !s.notificationDeliveryEnabled(user, "notification") {
			t.Fatal("channel delivery preference ignored")
		}
	})
	if _, e = s.FeedPreferences("foreign"); e == nil {
		t.Fatal("foreign profile read")
	}
}
func TestGlobalFeedPreferencesRejectActorAndUnknownChannels(t *testing.T) {
	s, user := feedTestServer(t)
	for _, body := range []string{`{"expected_revision":0,"actor":"other","in_app":{"enabled":false}}`, `{"expected_revision":0,"email":{"enabled":true}}`, `{"in_app":{"enabled":false}}`, `{"expected_revision":0,"in_app":{}}`} {
		rec := httptest.NewRecorder()
		s.HandleFeedPreferences(rec, withUser(httptest.NewRequest("PATCH", "/feed/preferences", bytes.NewBufferString(body)), user))
		if rec.Code != 400 {
			t.Fatalf("invalid body accepted: %s %d", body, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	s.HandleFeedPreferences(rec, httptest.NewRequest("GET", "/feed/preferences", nil))
	if rec.Code != 401 {
		t.Fatal("anonymous preferences")
	}
}
func TestGlobalPreferencesDoNotEraseAlertEvidence(t *testing.T) {
	s, user := feedTestServer(t)
	if e := s.changeForest(func() error {
		s.feedState().Attempts[user] = []core.FeedAttempt{{ID: "evidence", Outcome: "committed"}}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	rev := uint64(0)
	off := false
	if e := s.PatchFeedPreferences(user, FeedPreferencesPatch{ExpectedRevision: &rev, InApp: FeedChannelsPatch{Enabled: &off}}); e != nil {
		t.Fatal(e)
	}
	s.readForest(func() {
		if len(s.feedState().Attempts[user]) != 1 {
			t.Fatal("preferences erased evidence")
		}
		if s.notificationDeliveryEnabled(user, "alert") {
			t.Fatal("global disable ignored")
		}
	})
}
