// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"sort"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func (s *Server) accessViewLocked(path, userID string) (map[string]interface{}, error) {
	node, err := s.getNodeFromPath(path)
	if err != nil || !node.CheckPermission(userID, core.ReadPermission) {
		return nil, apiErrorf(404, "Item unavailable")
	}
	if node == s.forest {
		return nil, apiErrorf(400, "Account inventory cannot be shared")
	}
	g := s.accessGraphLocked()
	grants := []map[string]interface{}{}
	describe := func(grant core.AccessGrant) {
		profile, err := s.forest.GetUserProfile(grant.RecipientID)
		if err != nil {
			return
		}
		manageable := true
		for _, id := range accessTargets(g, grant) {
			if !g.nodes[id].CheckPermission(userID, core.AdminPermission) || grant.RecipientID == accessOwner(g.nodes[id]) {
				manageable = false
			}
		}
		if grant.RecipientID == userID || grant.RecipientID == accessOwner(node) {
			manageable = false
		}
		grants = append(grants, map[string]interface{}{"id": grant.ID, "username": profile.Username, "permission": int(grant.Permission), "scope": grant.Scope, "root_id": grant.RootID, "parent_id": grant.ParentID, "expires_at": grant.ExpiresAt, "can_manage": manageable})
	}
	if node.CreatedBy != "" {
		describe(core.AccessGrant{ID: "owner:" + node.ID + ":" + node.CreatedBy, RootID: node.ID, RecipientID: node.CreatedBy, Permission: core.AdminPermission, Scope: "item"})
	}
	for _, member := range node.Users {
		permission := -1
		for _, p := range member.Permissions {
			permission = max(permission, int(p))
		}
		describe(core.AccessGrant{ID: "direct:" + node.ID + ":" + member.ID, RootID: node.ID, RecipientID: member.ID, Permission: core.Permission(permission), Scope: "item"})
	}
	for _, grant := range s.forest.AccessPolicies {
		included := grant.RootID == node.ID
		for _, id := range accessTargets(g, grant) {
			if id == node.ID {
				included = true
			}
		}
		if included {
			describe(grant)
		}
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i]["id"].(string) < grants[j]["id"].(string) })
	return map[string]interface{}{"grants": grants, "recipients": s.accessRecipients(node, ""), "owner_id": accessOwner(node)}, nil
}

func (s *Server) accessPreviewLocked(request accessRequest, userID string) (map[string]interface{}, core.AccessGrant, []*core.Node, error) {
	if request.Action == "link" || request.Action == "unlink" {
		preview, err := s.linkAccessPreviewLocked(request, userID)
		return preview, core.AccessGrant{}, nil, err
	}
	empty := core.AccessGrant{}
	if request.Action != "grant" && request.Action != "revoke" {
		return nil, empty, nil, apiErrorf(400, "Choose grant, revoke, link, or unlink")
	}
	node, err := s.getNodeFromPath(request.Path)
	if err != nil || !node.CheckPermission(userID, core.ReadPermission) {
		return nil, empty, nil, apiErrorf(404, "Item unavailable")
	}
	if node == s.forest {
		return nil, empty, nil, apiErrorf(400, "Account inventory cannot be shared")
	}
	g := s.accessGraphLocked()
	grant := core.AccessGrant{ID: "proposed", RootID: node.ID, GrantorID: userID, Scope: request.Scope, ExpiresAt: request.ExpiresAt}
	if request.Action == "grant" {
		if request.Permission == nil || *request.Permission < 0 || *request.Permission > 2 {
			return nil, empty, nil, apiErrorf(400, "Choose viewer, editor, or manager")
		}
		grant.Permission = core.Permission(*request.Permission)
		if grant.Scope != "item" && grant.Scope != "existing" && grant.Scope != "ongoing" {
			return nil, empty, nil, apiErrorf(400, "Choose item, existing, or ongoing scope")
		}
		if grant.ExpiresAt < 0 || (grant.ExpiresAt > 0 && grant.ExpiresAt <= time.Now().Unix()) {
			return nil, empty, nil, apiErrorf(400, "Choose an expiry in the future")
		}
		for _, user := range s.forest.Users {
			if user.Username == request.Username {
				grant.RecipientID = user.ID
			}
		}
		if grant.RecipientID == "" {
			return nil, empty, nil, apiErrorf(404, "No account with that username")
		}
		if request.ParentPath != "" {
			parent, e := s.getNodeFromPath(request.ParentPath)
			if e != nil || !parent.CheckPermission(userID, core.ReadPermission) || parent.Children[node.ID] == nil {
				return nil, empty, nil, apiErrorf(400, "Choose an existing visible parent relationship")
			}
			grant.ParentID = parent.ID
		}
		if grant.Scope == "existing" {
			ongoing := grant
			ongoing.Scope = "ongoing"
			grant.TargetIDs = accessTargets(g, ongoing)
		}
	} else {
		if strings.HasPrefix(request.GrantID, "direct:"+node.ID+":") {
			grant.ID = request.GrantID
			grant.Scope = "item"
			grant.RecipientID = strings.TrimPrefix(request.GrantID, "direct:"+node.ID+":")
			found := false
			for _, user := range node.Users {
				if user.ID == grant.RecipientID {
					found = true
				}
			}
			if !found {
				return nil, empty, nil, apiErrorf(404, "Access source unavailable")
			}
		} else {
			var exists bool
			grant, exists = s.forest.AccessPolicies[request.GrantID]
			if !exists {
				return nil, empty, nil, apiErrorf(404, "Access source unavailable")
			}
			included := false
			for _, id := range accessTargets(g, grant) {
				if id == node.ID {
					included = true
				}
			}
			if !included && grant.RootID != node.ID {
				return nil, empty, nil, apiErrorf(404, "Access source does not include this item")
			}
		}
	}
	targets := []*core.Node{}
	items := []map[string]interface{}{}
	ids := accessTargets(g, grant)
	if request.Action == "revoke" && len(ids) == 0 && g.nodes[grant.RootID] != nil {
		ids = []string{grant.RootID}
	}
	for _, id := range ids {
		target := g.nodes[id]
		if target == s.forest || !target.CheckPermission(userID, core.AdminPermission) {
			return nil, empty, nil, apiErrorf(403, "Manage permission is required on every affected item")
		}
		if request.Action == "grant" && grant.RecipientID == accessOwner(target) && grant.Permission < core.AdminPermission {
			return nil, empty, nil, apiErrorf(409, "An owner cannot be downgraded")
		}
		if request.Action == "revoke" && (grant.RecipientID == userID || grant.RecipientID == accessOwner(target)) {
			return nil, empty, nil, apiErrorf(409, "Owners cannot be removed or remove their own access")
		}
		current := workPermission(target, grant.RecipientID)
		except := ""
		var extra *core.AccessGrant
		if request.Action == "revoke" {
			except = grant.ID
		} else {
			extra = &grant
		}
		sources := accessSources(target, grant.RecipientID, except, extra)
		title, _ := target.Metadata["title"].(string)
		if title == "" {
			title = target.Name
		}
		items = append(items, map[string]interface{}{"id": id, "path": g.paths[id], "title": title, "current_permission": current, "after_permission": accessSourcePermission(sources), "sources": sources})
		targets = append(targets, target)
	}
	profile, err := s.forest.GetUserProfile(grant.RecipientID)
	if err != nil {
		return nil, empty, nil, apiErrorf(404, "Recipient unavailable")
	}
	preview := map[string]interface{}{"revision": s.accessRevision(g, request, userID), "action": request.Action, "scope": grant.Scope, "future": grant.Scope == "ongoing", "items": items, "recipients": []map[string]interface{}{{"id": profile.ID, "username": profile.Username, "permission": int(grant.Permission)}}}
	return preview, grant, targets, nil
}

func (s *Server) creationAudience(node *core.Node, userID string) []map[string]interface{} {
	rights := map[string]int{}
	for _, grant := range node.AccessGrants {
		if grant.Scope != "ongoing" || grant.RecipientID == userID || (grant.ExpiresAt != 0 && grant.ExpiresAt <= time.Now().Unix()) {
			continue
		}
		if old, ok := rights[grant.RecipientID]; !ok || old < int(grant.Permission) {
			rights[grant.RecipientID] = int(grant.Permission)
		}
	}
	result := []map[string]interface{}{}
	for _, account := range s.forest.Users {
		if permission, ok := rights[account.ID]; ok {
			result = append(result, map[string]interface{}{"id": account.ID, "username": account.Username, "permission": permission})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i]["id"].(string) < result[j]["id"].(string) })
	return result
}
