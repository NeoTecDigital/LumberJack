package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"time"
)

// Board columns describe actual persisted lifecycle states. Queuing a plan
// does not start its clock; starting and finishing preserve its identity.
func workTransition(node *core.Node, userID, eventID, status string) error {
	if eventID == "" {
		return apiErrorf(400, "Choose an event")
	}
	event, live := node.Events[eventID]
	switch status {
	case "pending":
		if live {
			if event.Status == core.EventPending {
				return nil
			}
			return apiErrorf(409, "An event that started cannot be queued again")
		}
		plan, exists := node.PlannedEvents[eventID]
		if !exists {
			return apiErrorf(404, "Plan not found")
		}
		plan.StartTime, plan.EndTime = nil, nil
		plan.Status = core.EventPending
		plan.ModifiedBy, plan.ModifiedAt = userID, time.Now()
		node.Events[eventID] = plan
	case "ongoing":
		if live && event.Status == core.EventOngoing {
			return nil
		}
		if err := node.StartEvent(eventID, userID, nil, nil, nil); err != nil {
			return apiErrorf(409, "%v", err)
		}
	case "finished":
		if live && event.Status == core.EventFinished {
			return nil
		}
		if err := node.EndEvent(eventID, userID); err != nil {
			return apiErrorf(409, "%v", err)
		}
	default:
		return apiErrorf(400, "Choose queued, ongoing, or finished work")
	}
	return nil
}
