package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/core"
	"io"
	"net/http"
)

type FeedChannelsPatch struct {
	Enabled       *bool `json:"enabled,omitempty"`
	Reminders     *bool `json:"reminders,omitempty"`
	Notifications *bool `json:"notifications,omitempty"`
	Alerts        *bool `json:"alerts,omitempty"`
}
type FeedPreferencesPatch struct {
	ExpectedRevision *uint64           `json:"expected_revision"`
	InApp            FeedChannelsPatch `json:"in_app"`
}

func (s *Server) HandleFeedPreferences(w http.ResponseWriter, r *http.Request) {
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
		var patch FeedPreferencesPatch
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&patch) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "Invalid preferences update", 400)
			return
		}
		if e := s.PatchFeedPreferences(user, patch); e != nil {
			writeAPIError(w, e)
			return
		}
	}
	prefs, e := s.FeedPreferences(user)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(prefs)
}
func (s *Server) feedPreferences(user string) core.FeedPreferences {
	if s.forest.Correspondence != nil && s.forest.Correspondence.Feed != nil {
		if p, ok := s.forest.Correspondence.Feed.Preferences[user]; ok {
			return p
		}
	}
	return core.DefaultFeedPreferences()
}
func (s *Server) FeedPreferences(user string) (core.FeedPreferences, error) {
	var prefs core.FeedPreferences
	var failure error
	s.readForest(func() {
		if _, e := s.forest.GetUserProfile(user); e != nil {
			failure = apiErrorf(401, "Account unavailable")
			return
		}
		if !s.feedSnapshotDurable() {
			failure = apiErrorf(503, "Preferences durability unresolved")
			return
		}
		prefs = s.feedPreferences(user)
	})
	return prefs, failure
}
func (s *Server) PatchFeedPreferences(user string, patch FeedPreferencesPatch) error {
	p := patch.InApp
	if patch.ExpectedRevision == nil || (p.Enabled == nil && p.Reminders == nil && p.Notifications == nil && p.Alerts == nil) {
		return apiErrorf(400, "Provide revision and explicit channel preference")
	}
	e := s.changeForest(func() error {
		if _, e := s.forest.GetUserProfile(user); e != nil {
			return apiErrorf(401, "Account unavailable")
		}
		if !s.feedSnapshotDurable() {
			return apiErrorf(503, "Preferences durability unresolved")
		}
		prior := s.feedPreferences(user)
		if prior.Revision != *patch.ExpectedRevision {
			return apiErrorf(409, "Preferences revision changed")
		}
		if prior.Revision == ^uint64(0) {
			return apiErrorf(409, "Preferences revision exhausted")
		}
		applyFeedChannels(&prior.InApp, p)
		prior.Revision++
		feed := s.feedState()
		if feed.Preferences == nil {
			feed.Preferences = map[string]core.FeedPreferences{}
		}
		feed.Preferences[user] = prior
		return nil
	})
	if e == nil {
		s.publish(mutation("feed_preferences_updated", ""))
	}
	return e
}
func applyFeedChannels(c *core.FeedChannels, p FeedChannelsPatch) {
	if p.Enabled != nil {
		c.Enabled = *p.Enabled
	}
	if p.Reminders != nil {
		c.Reminders = *p.Reminders
	}
	if p.Notifications != nil {
		c.Notifications = *p.Notifications
	}
	if p.Alerts != nil {
		c.Alerts = *p.Alerts
	}
}

// Caller must already hold the forest; this function never writes state.
func (s *Server) notificationDeliveryEnabled(user, kind string) bool {
	c := s.feedPreferences(user).InApp
	if !c.Enabled {
		return false
	}
	switch kind {
	case "reminder", "reminder_due":
		return c.Reminders
	case "alert", "outcome":
		return c.Alerts
	default:
		return c.Notifications
	}
}
