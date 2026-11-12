// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "github.com/NeoTecDigital/LumberJack/core"

// Each request admits at most 10,000 examined descriptors, including denied
// nodes, ACL records, edges, empty entries/events, messages, edits and refs.
// Collection lengths are charged before traversal/allocation. Sorting is only
// performed after a successful bounded projection (at most 10,000 rows).
const assetIndexWorkLimit = 10000

type assetIndexBudget struct {
	used int
	err  error
}

func (b *assetIndexBudget) take(n int) bool {
	if b.err != nil {
		return false
	}
	if n > assetIndexWorkLimit-b.used {
		b.err = apiErrorf(503, "Asset index unavailable: scan budget exceeded")
		return false
	}
	b.used += n
	return true
}

func (b *assetIndexBudget) account(n *core.Node, user string) bool {
	if !b.take(len(n.Users)) {
		return false
	}
	for _, u := range n.Users {
		if u.ID == user {
			return true
		}
	}
	return false
}

func (b *assetIndexBudget) readable(n *core.Node, user string) bool {
	if !b.take(len(n.AccessGrants) + len(n.Users)) {
		return false
	}
	for _, u := range n.Users {
		if !b.take(len(u.Permissions)) {
			return false
		}
	}
	return n.CheckPermission(user, core.ReadPermission)
}

func (s *Server) assetScope(path string, b *assetIndexBudget) (*core.Node, error) {
	// Avoid getNodeFromPath's cache-miss full-forest cache reconstruction.
	if !b.take(len(path)) {
		return nil, b.err
	}
	current := s.forest
	for _, part := range s.segmentsFrom(path) {
		if !b.take(len(current.Children) + 1) {
			return nil, b.err
		}
		next := assetNamedChild(current, part)
		if next == nil {
			return nil, apiErrorf(404, "Asset scope unavailable")
		}
		current = next
	}
	return current, nil
}

func assetNamedChild(n *core.Node, name string) *core.Node {
	for _, child := range n.Children {
		if child != nil && child.Name == name {
			return child
		}
	}
	return nil
}

func (b *assetIndexBudget) fileVisible(c *core.Conversation, member core.ConversationMember, user, id string) bool {
	if c.Attachments[id].UploadedBy == user {
		return true
	}
	for _, m := range c.Messages {
		if !b.take(1) {
			return false
		}
		if m.Sequence <= member.From {
			continue
		}
		if b.references(m.Attachments, id) {
			return true
		}
		if !b.take(len(m.EditEvidence)) {
			return false
		}
		for _, edit := range m.EditEvidence {
			if b.references(edit.Attachments, id) {
				return true
			}
		}
	}
	return false
}

func (b *assetIndexBudget) references(refs []core.ConversationAttachmentRef, id string) bool {
	if !b.take(len(refs)) {
		return false
	}
	return referencesFile(refs, id)
}
