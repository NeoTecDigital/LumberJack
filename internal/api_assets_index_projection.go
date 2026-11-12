// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/core"
	"sort"
)

type assetWalk struct {
	node *core.Node
	path string
}

func (s *Server) nodeAssetItems(root *core.Node, path, user string, b *assetIndexBudget) []AssetIndexItem {
	items := []AssetIndexItem{}
	seen := map[string]bool{}
	queue := []assetWalk{{root, path}}
	for len(queue) > 0 {
		if !b.take(1) {
			return nil
		}
		next := queue[0]
		queue = queue[1:]
		n := next.node
		if n == nil || seen[n.ID] {
			continue
		}
		seen[n.ID] = true
		if b.readable(n, user) {
			items = append(items, nodeOwnedAssets(n, next.path, b)...)
		}
		if !b.take(len(n.Children)) {
			return nil
		}
		keys := make([]string, 0, len(n.Children))
		for k := range n.Children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := n.Children[k]
			if child != nil {
				queue = append(queue, assetWalk{child, next.path + "/" + child.Name})
			}
		}
	}
	return items
}
func nodeOwnedAssets(n *core.Node, path string, b *assetIndexBudget) []AssetIndexItem {
	items := []AssetIndexItem{}
	if !b.take(len(n.Attachments) + len(n.Events) + len(n.PlannedEvents)) {
		return nil
	}
	for _, file := range n.Attachments {
		items = append(items, nodeAsset(n, path, "", "", file))
	}
	items = append(items, entryAssets(n, path, "", n.Entries, b)...)
	for id, event := range n.Events {
		items = append(items, entryAssets(n, path, id, event.Entries, b)...)
	}
	for id, event := range n.PlannedEvents {
		items = append(items, entryAssets(n, path, id, event.Entries, b)...)
	}
	return items
}
func entryAssets(n *core.Node, path, event string, entries []core.Entry, b *assetIndexBudget) []AssetIndexItem {
	items := []AssetIndexItem{}
	if !b.take(len(entries)) {
		return nil
	}
	for _, entry := range entries {
		if !b.take(len(entry.Attachments)) {
			return nil
		}
		for _, file := range entry.Attachments {
			items = append(items, nodeAsset(n, path, event, entry.ID, file))
		}
	}
	return items
}
func nodeAsset(n *core.Node, path, event, entry string, file core.Attachment) AssetIndexItem {
	parent := n.ID
	if event != "" {
		parent = event
	}
	if entry != "" {
		parent = entry
	}
	return AssetIndexItem{ID: file.ID, OwnershipKind: "node", OwnerID: n.ID, ParentID: parent, Path: path, EventID: event, EntryID: entry, File: newAttachmentView(file)}
}
func (s *Server) conversationAssetItems(user string, b *assetIndexBudget) []AssetIndexItem {
	items := []AssetIndexItem{}
	if !b.take(len(s.forest.Conversations)) {
		return nil
	}
	for _, c := range s.forest.Conversations {
		member, ok := c.Members[user]
		if !ok || member.Invited {
			continue
		}
		items = append(items, conversationOwnedAssets(c, member, user, b)...)
	}
	return items
}
func conversationOwnedAssets(c *core.Conversation, member core.ConversationMember, user string, b *assetIndexBudget) []AssetIndexItem {
	items := []AssetIndexItem{}
	if !b.take(len(c.Attachments)) {
		return nil
	}
	for _, file := range c.Attachments {
		if !b.fileVisible(c, member, user, file.ID) {
			continue
		}
		view := map[string]interface{}{"id": file.ID, "size": file.Size, "uploaded_by": file.UploadedBy, "uploaded_at": file.UploadedAt, "name_envelope": append(json.RawMessage(nil), file.NameEnvelope...), "name_context": append(json.RawMessage(nil), file.NameContext...)}
		items = append(items, AssetIndexItem{ID: file.ID, OwnershipKind: "conversation", OwnerID: c.ID, ParentID: c.ID, Version: file.Version, File: view})
	}
	return items
}
