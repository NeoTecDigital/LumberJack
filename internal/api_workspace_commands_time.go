// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"sort"
	"time"
)

func (s *Server) workCommandTime(c *workCommandContext) error {
	node := c.node
	cmd := c.cmd
	userID := c.user
	start, end, err := workInterval(cmd.Start, cmd.End)
	if err != nil {
		return err
	}
	if end.After(time.Now()) {
		return apiErrorf(400, "Logged time must be in the past")
	}
	if workActive(node, userID) != nil {
		return apiErrorf(409, "Stop the active timer before adding a manual interval")
	}
	for _, span := range node.GetTimeTrackingSummary(userID) {
		from, a := span["start_time"].(time.Time)
		to, b := span["end_time"].(time.Time)
		if a && b && start.Before(to) && end.After(from) {
			return apiErrorf(409, "This interval overlaps time already logged here")
		}
	}
	if _, exists := node.Events[cmd.ClientID]; exists {
		return apiErrorf(409, "This event identity already exists")
	}
	node.Events[cmd.ClientID] = core.Event{StartTime: &start, EndTime: &end, Status: core.EventFinished,
		Realizes: node.ID, AssignedTo: userID, CreatedBy: userID, CreatedAt: time.Now(), ModifiedBy: userID, ModifiedAt: time.Now(),
		Metadata: map[string]interface{}{"title": cmd.Title, "manual": true}}
	first := node.AddEntry(core.TimeEntryStart, map[string]interface{}{"manual": true, "event_id": cmd.ClientID}, userID, "", "")
	node.Entries[len(node.Entries)-1].Timestamp = start
	node.AddEntry(core.TimeEntryStop, map[string]interface{}{"manual": true, "event_id": cmd.ClientID}, userID, "", "")
	node.Entries[len(node.Entries)-1].Timestamp = end
	sort.SliceStable(node.Entries, func(i, j int) bool { return node.Entries[i].Timestamp.Before(node.Entries[j].Timestamp) })
	c.result = map[string]interface{}{"id": first.ID}
	c.mutationKind = mutationEntryAdded
	return nil
}
