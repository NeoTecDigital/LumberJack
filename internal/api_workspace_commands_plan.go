// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import "github.com/NeoTecDigital/LumberJack/internal/core"

func (s *Server) workCommandPlan(c *workCommandContext) error {
	node := c.node
	cmd := c.cmd
	userID := c.user
	if cmd.EventID != "" {
		if _, exists := node.PlannedEvents[cmd.EventID]; exists && cmd.Revision != workRevision(node) {
			return apiErrorf(409, "Reload the latest plan before rescheduling it")
		}
	}
	start, end, err := workInterval(cmd.Start, cmd.End)
	if err != nil {
		return err
	}
	eventID := cmd.EventID
	if eventID == "" {
		eventID = cmd.ClientID
	}
	if cmd.AssignedTo != "" && !node.CheckPermission(cmd.AssignedTo, core.ReadPermission) {
		return apiErrorf(400, "Assign the plan to a member")
	}
	if err := node.PlanEvent(eventID, userID, &start, &end, map[string]interface{}{"title": cmd.Title}); err != nil {
		return apiErrorf(409, "%v", err)
	}
	planned := node.PlannedEvents[eventID]
	planned.Realizes = node.ID
	planned.AssignedTo = cmd.AssignedTo
	node.PlannedEvents[eventID] = planned
	c.result = map[string]interface{}{"event_id": eventID}
	c.mutationKind = mutationEventPlanned

	return nil
}
