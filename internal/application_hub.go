package internal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// Called while committing a command, so the work and its pending delivery are
// always part of the same durable snapshot. The hub never observes a half-write.
func (s *Server) enqueueCorrespondence(actor string, cmd WorkCommand, path string) {
	if cmd.Command == "preferences" || cmd.Command == "initialize" {
		return
	}
	node, err := s.getNodeFromPath(path)
	if err != nil {
		return
	}
	state := s.correspondenceState()
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(node.ID+"\x00"+actor+"\x00"+cmd.ClientID)))
	recipients := []string{}
	for _, user := range s.forest.Users {
		if user.ID != SystemUserID && user.ID != actor && node.CheckPermission(user.ID, core.ReadPermission) {
			recipients = append(recipients, user.ID)
		}
	}
	sort.Strings(recipients)
	state.Pending[id] = core.CorrespondenceChange{ID: id, PinID: node.ID, Path: s.canonicalPath(path),
		Actor: actor, Operation: cmd.Command, At: time.Now().UTC().Format(time.RFC3339Nano), Recipients: recipients}
}

func (s *Server) correspondenceState() *core.CorrespondenceState {
	if s.forest.Correspondence == nil {
		s.forest.Correspondence = &core.CorrespondenceState{}
	}
	state := s.forest.Correspondence
	if state.Pending == nil {
		state.Pending = map[string]core.CorrespondenceChange{}
	}
	if state.Inbox == nil {
		state.Inbox = map[string][]core.CorrespondenceNotification{}
	}
	return state
}

// ApplicationHub is a trusted native capability, not an HTTP route. Corresponder
// alone pulls pending records and acknowledges dispatcher delivery — for the
// user-to-user inbox (pending/deliver) and for the external outbox the MFA path
// fills (outbound/outbound_ack). Browser requests cannot manufacture this call by
// choosing a path or sending a header.
func (s *Server) ApplicationHub(raw []byte) ([]byte, error) {
	var request struct {
		Operation string `json:"operation"`
		ID        string `json:"id"`
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		return nil, err
	}
	var result interface{}
	switch request.Operation {
	case "pending", "status":
		s.readForest(func() {
			state := s.forest.Correspondence
			pending := []core.CorrespondenceChange{}
			var delivered uint64
			last := ""
			if state != nil {
				for _, item := range state.Pending {
					pending = append(pending, item)
				}
				delivered, last = state.Delivered, state.LastDelivery
			}
			sort.Slice(pending, func(i, j int) bool {
				if pending[i].At == pending[j].At {
					return pending[i].ID < pending[j].ID
				}
				return pending[i].At < pending[j].At
			})
			oldest := ""
			if len(pending) > 0 {
				oldest = pending[0].At
			}
			if request.Operation == "status" {
				result = map[string]interface{}{"pending": len(pending), "delivered": delivered, "last_delivery": last, "oldest_pending": oldest}
			} else {
				if len(pending) > 128 {
					pending = pending[:128]
				}
				result = pending
			}
		})
	case "outbound":
		// The external outbox, the read twin of "pending": the OutboundMessage items the MFA path
		// enqueues for a channel off this portal. Read-only, oldest-first by CreatedAt so the
		// forward-dispatcher forwards them in the order they were queued, and capped at 128 like the
		// pending list so one drain is bounded. A stale-cursor retry re-reads; it never mutates here.
		s.readForest(func() {
			state := s.forest.Correspondence
			outbound := []core.OutboundMessage{}
			if state != nil {
				for _, item := range state.Outbound {
					outbound = append(outbound, item)
				}
			}
			sort.Slice(outbound, func(i, j int) bool {
				if outbound[i].CreatedAt == outbound[j].CreatedAt {
					return outbound[i].ID < outbound[j].ID
				}
				return outbound[i].CreatedAt < outbound[j].CreatedAt
			})
			if len(outbound) > 128 {
				outbound = outbound[:128]
			}
			result = outbound
		})
	case "deliver":
		var path string
		err := s.changeForest(func() error {
			state := s.correspondenceState()
			change, found := state.Pending[request.ID]
			if !found {
				result = map[string]interface{}{"delivered": false}
				return nil
			}
			node, err := s.getNodeFromPath(change.Path)
			count := 0
			if err == nil && node.ID == change.PinID {
				for _, recipient := range change.Recipients {
					if !node.CheckPermission(recipient, core.ReadPermission) {
						continue
					}
					if _, err := s.forest.GetUserProfile(recipient); err != nil {
						continue
					}
					inbox := state.Inbox[recipient]
					found := false
					for _, notification := range inbox {
						if notification.Change.ID == change.ID {
							found = true
							break
						}
					}
					if !found {
						// Recipients themselves are private routing information.
						copy := change
						copy.Recipients = nil
						inbox = append(inbox, core.CorrespondenceNotification{Change: copy})
						if len(inbox) > 200 {
							inbox = inbox[len(inbox)-200:]
						}
						state.Inbox[recipient] = inbox
						count++
					}
				}
				path = change.Path
			}
			delete(state.Pending, request.ID)
			state.Delivered++
			state.LastDelivery = time.Now().UTC().Format(time.RFC3339Nano)
			result = map[string]interface{}{"delivered": true, "recipients": count}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if path != "" {
			s.publish(mutation("notification_delivered", path))
		}
	case "outbound_ack":
		// The external outbox's "deliver": once the forward-dispatcher has handed an item to the
		// carrier, it clears that id under the exclusive hold so the item is not re-sent, exactly as
		// "deliver" removes a pending record. A miss answers acked:false rather than erroring — a
		// racing retry that already cleared the id, or an id that never existed, is benign, matching
		// deliver's {"delivered": false} for a not-found id — so the dispatcher never retries a phantom.
		err := s.changeForest(func() error {
			state := s.correspondenceState()
			if _, found := state.Outbound[request.ID]; !found {
				result = map[string]interface{}{"acked": false}
				return nil
			}
			delete(state.Outbound, request.ID)
			result = map[string]interface{}{"acked": true}
			return nil
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown hub operation")
	}
	return json.Marshal(result)
}

func (s *Server) handleApplicationPrincipal(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r)
	s.readForest(func() {
		profile, err := s.forest.GetUserProfile(userID)
		if err != nil {
			http.Error(w, "Account unavailable", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"id": profile.ID, "username": profile.Username, "admin": s.forest.CheckPermission(userID, core.AdminPermission)})
	})
}

func (s *Server) handleApplicationNotifications(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFrom(r)
	if r.Method == "POST" {
		var input struct {
			ID string `json:"id"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.ID == "" {
			http.Error(w, "Choose a notification", 400)
			return
		}
		readPath := ""
		err := s.changeForest(func() error {
			if _, err := s.forest.GetUserProfile(userID); err != nil {
				return apiErrorf(401, "Account unavailable")
			}
			state := s.correspondenceState()
			for i, item := range state.Inbox[userID] {
				if item.Change.ID == input.ID && item.ReadAt == "" {
					state.Inbox[userID][i].ReadAt = time.Now().UTC().Format(time.RFC3339Nano)
					readPath = item.Change.Path
				}
			}
			return nil
		})
		if err != nil {
			writeAPIError(w, err)
			return
		}
		if readPath != "" {
			s.publish(mutation("notification_read", readPath))
		}
	}
	s.readForest(func() {
		if _, err := s.forest.GetUserProfile(userID); err != nil {
			http.Error(w, "Account unavailable", 401)
			return
		}
		items := []map[string]interface{}{}
		if state := s.forest.Correspondence; state != nil {
			for _, item := range state.Inbox[userID] {
				c := item.Change
				node, err := s.getNodeFromPath(c.Path)
				if err != nil || node.ID != c.PinID || !node.CheckPermission(userID, core.ReadPermission) {
					continue
				}
				actor := "A member"
				if profile, err := s.forest.GetUserProfile(c.Actor); err == nil {
					actor = profile.Username
				}
				items = append(items, map[string]interface{}{"id": c.ID, "pin_id": c.PinID, "path": c.Path, "operation": c.Operation, "actor": actor, "at": c.At, "read_at": item.ReadAt, "title": node.Metadata["title"]})
			}
		}
		sort.Slice(items, func(i, j int) bool { return items[i]["at"].(string) > items[j]["at"].(string) })
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"items": items})
	})
}
