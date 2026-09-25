// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

type accessRequest struct {
	Action     string `json:"action"`
	Path       string `json:"path"`
	Username   string `json:"username,omitempty"`
	Permission *int   `json:"permission,omitempty"`
	Scope      string `json:"scope,omitempty"`
	ParentPath string `json:"parent_path,omitempty"`
	ChildPath  string `json:"child_path,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
	GrantID    string `json:"grant_id,omitempty"`
	Revision   string `json:"revision,omitempty"`
}
type accessGraph struct {
	nodes map[string]*core.Node
	paths map[string]string
}

func (s *Server) accessGraphLocked() accessGraph {
	g := accessGraph{nodes: map[string]*core.Node{}, paths: map[string]string{}}
	_ = s.walkScope("", nil, func(at visit) { g.nodes[at.node.ID] = at.node; g.paths[at.node.ID] = at.path })
	return g
}
func accessOwner(node *core.Node) string {
	if node.CreatedBy != "" {
		return node.CreatedBy
	}
	// Preserve legacy ownership; never infer the current caller as owner.
	for _, user := range node.Users {
		for _, p := range user.Permissions {
			if p == core.AdminPermission {
				return user.ID
			}
		}
	}
	return ""
}
func accessTargets(g accessGraph, grant core.AccessGrant) []string {
	root := g.nodes[grant.RootID]
	if root == nil {
		return nil
	}
	if grant.ParentID != "" {
		parent := g.nodes[grant.ParentID]
		if parent == nil || parent.Children[root.ID] == nil {
			return nil
		}
	}
	if grant.Scope == "item" {
		return []string{root.ID}
	}
	if grant.Scope == "existing" {
		ids := []string{}
		for _, id := range grant.TargetIDs {
			if g.nodes[id] != nil {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		return ids
	}
	ids := []string{}
	seen := map[string]bool{}
	queue := []*core.Node{root}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if node == nil || seen[node.ID] {
			continue
		}
		seen[node.ID] = true
		ids = append(ids, node.ID)
		for _, child := range node.Children {
			queue = append(queue, child)
		}
	}
	sort.Strings(ids)
	return ids
}
func (s *Server) refreshAccessGrantsLocked() {
	g := s.accessGraphLocked()
	for _, node := range g.nodes {
		node.AccessGrants = nil
	}
	for id, grant := range s.forest.AccessPolicies {
		if grant.ExpiresAt != 0 && grant.ExpiresAt <= time.Now().Unix() {
			continue
		}
		for _, targetID := range accessTargets(g, grant) {
			node := g.nodes[targetID]
			if node == s.forest {
				continue
			}
			if node.AccessGrants == nil {
				node.AccessGrants = map[string]core.AccessGrant{}
			}
			node.AccessGrants[id] = grant
		}
	}
}
func accessSources(node *core.Node, userID, except string, extra *core.AccessGrant) []map[string]interface{} {
	sources := []map[string]interface{}{}
	if userID != "" && node.CreatedBy == userID {
		sources = append(sources, map[string]interface{}{"id": "owner:" + node.ID + ":" + userID, "scope": "item", "permission": int(core.AdminPermission), "root_id": node.ID})
	}
	for _, member := range node.Users {
		id := "direct:" + node.ID + ":" + member.ID
		if member.ID != userID || id == except {
			continue
		}
		permission := -1
		for _, p := range member.Permissions {
			permission = max(permission, int(p))
		}
		if permission >= 0 {
			sources = append(sources, map[string]interface{}{"id": id, "scope": "item", "permission": permission, "root_id": node.ID})
		}
	}
	for id, grant := range node.AccessGrants {
		if id == except || grant.RecipientID != userID || (grant.ExpiresAt != 0 && grant.ExpiresAt <= time.Now().Unix()) {
			continue
		}
		sources = append(sources, map[string]interface{}{"id": id, "scope": grant.Scope, "permission": int(grant.Permission), "root_id": grant.RootID})
	}
	if extra != nil {
		sources = append(sources, map[string]interface{}{"id": extra.ID, "scope": extra.Scope, "permission": int(extra.Permission), "root_id": extra.RootID})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i]["id"].(string) < sources[j]["id"].(string) })
	return sources
}
func accessSourcePermission(sources []map[string]interface{}) int {
	permission := -1
	for _, source := range sources {
		permission = max(permission, source["permission"].(int))
	}
	return permission
}
func (s *Server) accessRecipients(node *core.Node, exclude string) []map[string]interface{} {
	recipients := []map[string]interface{}{}
	for _, user := range s.forest.Users {
		if user.ID == exclude {
			continue
		}
		if permission := workPermission(node, user.ID); permission >= 0 {
			recipients = append(recipients, map[string]interface{}{"id": user.ID, "username": user.Username, "permission": permission})
		}
	}
	sort.Slice(recipients, func(i, j int) bool { return recipients[i]["id"].(string) < recipients[j]["id"].(string) })
	return recipients
}
func (s *Server) accessRevision(g accessGraph, request accessRequest, userID string) string {
	request.Revision = ""
	nodes := map[string]interface{}{}
	for id, node := range g.nodes {
		nodes[id] = []interface{}{node.Name, node.Metadata["title"], node.CreatedBy, node.Parents, newUserViews(node.Users), node.AccessGrants}
	}
	live := map[string]bool{}
	for id, grant := range s.forest.AccessPolicies {
		live[id] = grant.ExpiresAt == 0 || grant.ExpiresAt > time.Now().Unix()
	}
	data, _ := json.Marshal([]interface{}{userID, request, nodes, s.forest.AccessPolicies, live})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "Sign in required", 401)
		return
	}
	var result map[string]interface{}
	var failure error
	if r.Method == http.MethodGet {
		s.readForest(func() { result, failure = s.accessViewLocked(r.URL.Query().Get("path"), userID) })
	} else {
		var request accessRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "Invalid sharing request", 400)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/preview") {
			s.readForest(func() { result, _, _, failure = s.accessPreviewLocked(request, userID) })
		} else {
			failure = s.changeForest(func() error {
				preview, grant, targets, err := s.accessPreviewLocked(request, userID)
				if err != nil {
					return err
				}
				if request.Revision == "" || request.Revision != preview["revision"] {
					return apiErrorf(409, "Sharing changed. Review a fresh preview before applying.")
				}
				if request.Action == "link" || request.Action == "unlink" {
					return apiErrorf(400, "Apply relationships through /nodes/link")
				}
				if s.forest.Correspondence != nil && len(s.forest.Correspondence.Pending) >= 4096 {
					return apiErrorf(503, "Notification delivery is backlogged; retry sharing later")
				}
				if request.Action == "grant" {
					grant.ID = "grant-" + core.GenerateEntryID()
					if s.forest.AccessPolicies == nil {
						s.forest.AccessPolicies = map[string]core.AccessGrant{}
					}
					s.forest.AccessPolicies[grant.ID] = grant
				} else if strings.HasPrefix(grant.ID, "direct:") {
					for _, node := range targets {
						kept := []core.User{}
						for _, user := range node.Users {
							if user.ID != grant.RecipientID {
								kept = append(kept, user)
							}
						}
						node.Users = kept
					}
				} else {
					delete(s.forest.AccessPolicies, grant.ID)
				}
				s.refreshAccessGrantsLocked()
				for _, node := range targets {
					s.stopRevokedAccessTimer(node, grant.RecipientID, userID)
				}
				// Stage the notice in the same snapshot as the access change. The hub
				// checks current rights again on delivery and notification reads.
				graph := s.accessGraphLocked()
				if root := graph.nodes[grant.RootID]; root != nil && grant.RecipientID != userID && root.CheckPermission(grant.RecipientID, core.ReadPermission) {
					profile, _ := s.forest.GetUserProfile(grant.RecipientID)
					s.enqueueCorrespondence(userID, WorkCommand{Command: "share", Username: profile.Username, ClientID: "access:" + request.Action + ":" + grant.ID}, graph.paths[root.ID])
				}
				result = map[string]interface{}{"grant_id": grant.ID, "applied": true}
				return nil
			})
			if failure == nil {
				s.publish(mutation(mutationMetadataSet, s.canonicalPath(request.Path)))
			}
		}
	}
	if failure != nil {
		writeAPIError(w, failure)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
func (s *Server) stopRevokedAccessTimer(node *core.Node, recipient, actor string) {
	if node.CheckPermission(recipient, core.WritePermission) {
		return
	}
	active := workActive(node, recipient)
	if active == nil {
		return
	}
	eventID, _ := active.Metadata["event_id"].(string)
	if event, exists := node.Events[eventID]; exists && event.EndTime == nil {
		now := time.Now()
		event.EndTime, event.Status = &now, core.EventFinished
		event.ModifiedBy, event.ModifiedAt = actor, now
		node.Events[eventID] = event
	}
	node.AddEntry(core.TimeEntryStop, map[string]interface{}{"event_id": eventID, "stopped_by": actor, "reason": "access_changed"}, recipient, "", "")
}
