// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/core"
	"time"
)

func feedIdentity(parts ...string) string {
	raw, _ := json.Marshal(parts)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
func (s *Server) feedState() *core.FeedState {
	state := s.correspondenceState()
	if state.Feed == nil {
		state.Feed = &core.FeedState{}
	}
	feed := state.Feed
	if feed.Attempts == nil {
		feed.Attempts = map[string][]core.FeedAttempt{}
	}
	if feed.Marks == nil {
		feed.Marks = map[string]map[string]core.FeedMark{}
	}
	if feed.Receipts == nil {
		feed.Receipts = map[string]core.FeedReceipt{}
	}
	if feed.Reminders == nil {
		feed.Reminders = map[string]core.ReminderOccurrence{}
	}
	return feed
}
func (s *Server) existingFeedReceipt(user string, cmd WorkCommand, digest string) (core.FeedReceipt, bool, error) {
	state := s.forest.Correspondence
	if state == nil || state.Feed == nil {
		return core.FeedReceipt{}, false, nil
	}
	receipt, found := state.Feed.Receipts[feedIdentity(user, cmd.ClientID)]
	if found && receipt.Digest != digest {
		return receipt, true, apiErrorf(409, "This command identity was already used")
	}
	return receipt, found, nil
}
func (s *Server) appendFeedAttempt(user string, cmd WorkCommand, digest, nodeID, path, outcome string, status int) {
	feed := s.feedState()
	id := feedIdentity(user, cmd.ClientID, digest, outcome)
	for _, attempt := range feed.Attempts[user] {
		if attempt.ID == id {
			return
		}
	}
	feed.Attempts[user] = append(feed.Attempts[user], core.FeedAttempt{ID: id, CommandID: cmd.ClientID, Digest: digest, NodeID: nodeID, Path: path, Operation: cmd.Command, Outcome: outcome, Status: status, At: time.Now().UTC().Format(time.RFC3339Nano)})
}
func (s *Server) commitFeedSuccess(user string, cmd WorkCommand, digest string, node *core.Node, path string, result []byte) {
	s.appendFeedAttempt(user, cmd, digest, node.ID, path, "success", 200)
	s.feedState().Receipts[feedIdentity(user, cmd.ClientID)] = core.FeedReceipt{Digest: digest, Status: 200, Result: append([]byte(nil), result...)}
}

// Record only known definitive validation failures after a successful fsync.
// Unknown persistence/transport errors never become fabricated failed outcomes.
func (s *Server) recordWorkRefusal(user string, cmd WorkCommand, digest string, failure error) error {
	carried := new(apiError)
	if !asAPIError(failure, &carried) || carried.status < 400 || carried.status >= 500 || carried.status == 401 || cmd.ClientID == "" || len(cmd.ClientID) > 100 {
		return failure
	}
	err := s.changeForest(func() error {
		if !s.feedSnapshotDurable() {
			return apiErrorf(503, "Outcome snapshot durability unresolved")
		}
		if _, err := s.forest.GetUserProfile(user); err != nil {
			return apiErrorf(401, "Account unavailable")
		}
		nodeID, path := "", ""
		if node, err := s.getNodeFromPath(cmd.Path); err == nil && node.CheckPermission(user, core.ReadPermission) {
			nodeID, path = node.ID, cmd.Path
		}
		s.appendFeedAttempt(user, cmd, digest, nodeID, path, "failure", carried.status)
		key := feedIdentity(user, cmd.ClientID)
		if _, exists := s.feedState().Receipts[key]; !exists {
			s.feedState().Receipts[key] = core.FeedReceipt{Digest: digest, Status: carried.status}
		}
		return nil
	})
	if err != nil {
		return apiErrorf(503, "Outcome unresolved; read this command identity before retrying")
	}
	s.publish(mutation("feed_outcome", ""))
	return failure
}
