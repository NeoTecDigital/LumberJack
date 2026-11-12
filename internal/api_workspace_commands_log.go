// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"github.com/NeoTecDigital/LumberJack/core"
	"strings"
)

func (s *Server) workCommandLog(c *workCommandContext) error {
	node := c.node
	cmd := c.cmd
	userID := c.user
	if cmd.Content == core.TimeEntryStart || cmd.Content == core.TimeEntryStop {
		return apiErrorf(400, "Use the timer controls to record a time boundary")
	}
	if strings.TrimSpace(cmd.Content) == "" {
		return apiErrorf(400, "Write something to log")
	}
	if cmd.ParentID != "" {
		found := false
		for _, entry := range node.Entries {
			if entry.ID == cmd.ParentID {
				found = true
			}
		}
		if !found {
			return apiErrorf(400, "The reply target is not on this work")
		}
	}
	entry := node.AddEntry(cmd.Content, map[string]interface{}{"client_id": cmd.ClientID, "category": "log"}, userID, cmd.ParentID, "")
	c.result = newEntryView(entry)
	c.mutationKind = mutationEntryAdded
	return nil
}
