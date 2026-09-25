package internal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"sort"
	"time"
)

// The compatibility API also writes through the same transaction boundary.
// Capture changed resources there, so files, entry edits and event operations
// cannot bypass durable correspondence simply by using a legacy route.
type correspondenceSnapshot struct {
	revisions map[string]string
	pending   map[string]bool
}

func notificationRevision(node *core.Node) string {
	metadata := workMetadata(node)
	delete(metadata, "preferences") // personal presentation settings are not news
	body, _ := json.Marshal([]interface{}{node.Kind, metadata, newEntryViews(node.Entries), newEventViews(node.Events),
		newEventViews(node.PlannedEvents), newAttachmentViews(node.Attachments), newUserViews(node.Users)})
	return fmt.Sprintf("%x", sha256.Sum256(body))
}

func (s *Server) captureCorrespondence() *correspondenceSnapshot {
	before := &correspondenceSnapshot{revisions: map[string]string{}, pending: map[string]bool{}}
	_ = s.walkScope("", nil, func(at visit) {
		if at.node != s.forest {
			before.revisions[at.node.ID] = notificationRevision(at.node)
		}
	})
	if state := s.forest.Correspondence; state != nil {
		for id := range state.Pending {
			before.pending[id] = true
		}
	}
	return before
}

func (s *Server) recordCompatibilityChanges(before *correspondenceSnapshot) {
	queued := map[string]bool{}
	if state := s.forest.Correspondence; state != nil {
		for id, item := range state.Pending {
			if !before.pending[id] {
				queued[item.PinID] = true
			}
		}
	}
	_ = s.walkScope("", nil, func(at visit) {
		node := at.node
		if node == s.forest || queued[node.ID] || before.revisions[node.ID] == notificationRevision(node) {
			return
		}
		recipients := []string{}
		for _, user := range s.forest.Users {
			if user.ID != SystemUserID && node.CheckPermission(user.ID, core.ReadPermission) && s.forest.Subscriptions[user.ID][node.ID] {
				recipients = append(recipients, user.ID)
			}
		}
		// Legacy writes may lack an author stamp. Only explicit subscribers get
		// neutral updates; a resource ACL is not a notification subscription.
		if len(recipients) == 0 {
			return
		}
		sort.Strings(recipients)
		id := fmt.Sprintf("%x", sha256.Sum256([]byte(core.GenerateUserID()+node.ID)))
		s.correspondenceState().Pending[id] = core.CorrespondenceChange{ID: id, PinID: node.ID, Path: at.path, Operation: "update",
			At: time.Now().UTC().Format(time.RFC3339Nano), Recipients: recipients}
		queued[node.ID] = true
	})
}
