// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"sort"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// Simulate the new relationship on shallow graph copies. Previewing must never
// change live children, parent maps, or materialized rights, even temporarily.
func (s *Server) linkAccessPreviewLocked(request accessRequest, userID string) (map[string]interface{}, error) {
	request = accessRequest{Action: request.Action, ParentPath: strings.Trim(request.ParentPath, "/"), ChildPath: strings.Trim(request.ChildPath, "/")}
	if request.Action != "link" && request.Action != "unlink" {
		return nil, apiErrorf(400, "Choose link or unlink")
	}
	if request.ParentPath == "" || request.ChildPath == "" {
		return nil, apiErrorf(400, "Both relationship endpoints are required")
	}
	parent, err := s.getNodeFromPath(request.ParentPath)
	if err != nil {
		return nil, apiErrorf(404, "Parent unavailable")
	}
	child, err := s.getNodeFromPath(request.ChildPath)
	if err != nil {
		return nil, apiErrorf(404, "Child unavailable")
	}
	if !parent.CheckPermission(userID, core.WritePermission) || !child.CheckPermission(userID, core.WritePermission) {
		return nil, apiErrorf(403, "Edit permission is required on both relationship endpoints")
	}
	if request.Action == "link" && (parent.ID == child.ID || reaches(child, parent.ID)) {
		return nil, apiErrorf(400, "This relationship would create a cycle")
	}
	if request.Action == "unlink" {
		if parent.Children[child.ID] == nil {
			return nil, apiErrorf(404, "The relationship does not exist")
		}
		if len(child.Parents) <= 1 {
			return nil, apiErrorf(409, "Unlinking the last parent would strand this item")
		}
	}
	original := s.accessGraphLocked()
	simulated := accessGraph{nodes: map[string]*core.Node{}, paths: original.paths}
	for id, node := range original.nodes {
		copy := &core.Node{ID: node.ID, Name: node.Name, CreatedBy: node.CreatedBy,
			Users: node.Users, Metadata: node.Metadata, Children: map[string]*core.Node{}, Parents: map[string]string{}}
		for parentID, name := range node.Parents {
			copy.Parents[parentID] = name
		}
		simulated.nodes[id] = copy
	}
	for id, node := range original.nodes {
		for childID := range node.Children {
			simulated.nodes[id].Children[childID] = simulated.nodes[childID]
		}
	}
	if request.Action == "link" {
		simulated.nodes[parent.ID].Children[child.ID] = simulated.nodes[child.ID]
		simulated.nodes[child.ID].Parents[parent.ID] = parent.Name
	} else {
		delete(simulated.nodes[parent.ID].Children, child.ID)
		delete(simulated.nodes[child.ID].Parents, parent.ID)
	}
	for _, node := range simulated.nodes {
		node.AccessGrants = map[string]core.AccessGrant{}
	}
	for id, grant := range s.forest.AccessPolicies {
		if grant.ExpiresAt != 0 && grant.ExpiresAt <= time.Now().Unix() {
			continue
		}
		for _, nodeID := range accessTargets(simulated, grant) {
			if nodeID != s.forest.ID {
				simulated.nodes[nodeID].AccessGrants[id] = grant
			}
		}
	}
	items := []map[string]interface{}{}
	recipients := map[string]map[string]interface{}{}
	ids := []string{}
	for id := range simulated.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		node := original.nodes[id]
		after := simulated.nodes[id]
		for _, account := range s.forest.Users {
			beforePermission, afterPermission := workPermission(node, account.ID), workPermission(after, account.ID)
			if afterPermission == beforePermission {
				continue
			}
			if !parent.CheckPermission(userID, core.AdminPermission) || !node.CheckPermission(userID, core.AdminPermission) {
				return nil, apiErrorf(403, "Manage permission is required on the source parent and every item whose audience changes")
			}
			title, _ := node.Metadata["title"].(string)
			if title == "" {
				title = node.Name
			}
			items = append(items, map[string]interface{}{"id": id, "path": original.paths[id], "title": title, "recipient_id": account.ID, "username": account.Username, "current_permission": beforePermission, "after_permission": afterPermission, "sources": accessSources(after, account.ID, "", nil)})
			if existing, ok := recipients[account.ID]; !ok || existing["permission"].(int) < afterPermission {
				recipients[account.ID] = map[string]interface{}{"id": account.ID, "username": account.Username, "permission": afterPermission}
			}
		}
	}
	people := []map[string]interface{}{}
	for _, account := range s.forest.Users {
		if person := recipients[account.ID]; person != nil {
			people = append(people, person)
		}
	}
	return map[string]interface{}{"revision": s.accessRevision(original, request, userID), "action": request.Action, "scope": "ongoing", "future": len(items) > 0, "items": items, "recipients": people}, nil
}
