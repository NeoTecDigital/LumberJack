package internal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/internal/graph"
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

// recordTrackedChanges is recordCompatibilityChanges for a change that says which nodes it wrote:
// an update is queued for every node whose content changed and that a reader is subscribed to.
// No walk and no before-image are needed, because the writer vouches for what changed. It answers
// whether anything was queued, which is a write to the forest root.
func (s *Server) recordTrackedChanges(touched *graph.Touched) bool {
	queued := false
	for _, touch := range touched.List() {
		node := touch.Node
		if !touch.Content || node == s.forest {
			continue
		}
		recipients := s.subscribersOf(node)
		if len(recipients) == 0 {
			continue
		}
		s.queueUpdate(node, s.pathOfLocked(node), recipients)
		queued = true
	}
	return queued
}

// subscribersOf is every reader subscribed to a node who may read it, sorted.
func (s *Server) subscribersOf(node *core.Node) []string {
	recipients := []string{}
	for _, user := range s.forest.Users {
		if user.ID != SystemUserID && node.CheckPermission(user.ID, core.ReadPermission) && s.forest.Subscriptions[user.ID][node.ID] {
			recipients = append(recipients, user.ID)
		}
	}
	sort.Strings(recipients)
	return recipients
}

// queueUpdate files one update for a node in the hub's outbox.
func (s *Server) queueUpdate(node *core.Node, path string, recipients []string) {
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(core.GenerateUserID()+node.ID)))
	s.correspondenceState().Pending[id] = core.CorrespondenceChange{ID: id, PinID: node.ID, Path: path, Operation: "update",
		At: time.Now().UTC().Format(time.RFC3339Nano), Recipients: recipients}
}

// pathOfLocked is a node's canonical path, found by walking the forest. It is paid only for a
// node a reader is subscribed to. The caller holds the forest.
func (s *Server) pathOfLocked(target *core.Node) string {
	path := ""
	_ = s.walkScope("", nil, func(at visit) {
		if at.node == target && path == "" {
			path = at.path
		}
	})
	return path
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
		// Legacy writes may lack an author stamp. Only explicit subscribers get
		// neutral updates; a resource ACL is not a notification subscription.
		recipients := s.subscribersOf(node)
		if len(recipients) == 0 {
			return
		}
		s.queueUpdate(node, at.path, recipients)
		queued[node.ID] = true
	})
}
