// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func (s *Server) workCommandTimerStart(c *workCommandContext) error {
	node := c.node
	cmd := c.cmd
	userID := c.user
	var activePath string
	_ = s.walkScope("", nil, func(at visit) {
		if workActive(at.node, userID) != nil {
			activePath = at.path
		}
	})
	if activePath != "" {
		return apiErrorf(409, "Stop your timer on %s before starting another", activePath)
	}
	eventID := cmd.EventID
	if eventID == "" {
		eventID = cmd.ClientID
	}
	var metadata map[string]interface{}
	if cmd.EventID == "" {
		metadata = map[string]interface{}{"title": node.Metadata["title"]}
	}
	if err := node.StartEvent(eventID, userID, nil, nil, metadata); err != nil {
		return apiErrorf(409, "%v", err)
	}
	event := node.Events[eventID]
	event.Realizes, event.AssignedTo = node.ID, userID
	node.Events[eventID] = event
	node.Metadata["status"] = "active"
	entry := node.AddEntry(core.TimeEntryStart, map[string]interface{}{"client_id": cmd.ClientID, "event_id": eventID}, userID, "", "")
	c.result = newEntryView(entry)
	c.mutationKind = mutationEntryAdded
	return nil
}
