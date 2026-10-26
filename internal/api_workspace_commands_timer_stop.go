// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func (s *Server) workCommandTimerStop(c *workCommandContext) error {
	node := c.node
	cmd := c.cmd
	userID := c.user
	active := workActive(node, userID)
	if active == nil || active.ID != cmd.EventID {
		return apiErrorf(409, "That timer is no longer running. Refresh to see the current timer.")
	}
	eventID, _ := active.Metadata["event_id"].(string)
	if event, exists := node.Events[eventID]; exists && event.EndTime == nil {
		if err := node.EndEvent(eventID, userID); err != nil {
			return apiErrorf(409, "%v", err)
		}
	}
	entry := node.AddEntry(core.TimeEntryStop, map[string]interface{}{"event_id": eventID}, userID, "", "")
	c.result = newEntryView(entry)
	c.mutationKind = mutationEntryAdded
	return nil
}
