// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/core"
	"time"
)

func eventTemporal(event core.Event) temporalInput {
	var value temporalInput
	raw, _ := json.Marshal(event.Metadata[temporalKey])
	_ = json.Unmarshal(raw, &value)
	if value.Type != "" {
		return value
	}
	value.Type, value.Status = "action", "planned"
	if event.Status == core.EventOngoing {
		value.Status = "active"
	}
	if event.Status == core.EventFinished {
		value.Type, value.Status, value.Outcome = "event", "done", "completed"
	}
	return value
}

func (s *Server) workLegacyTemporal(c *workCommandContext) error {
	id, value := c.cmd.EventID, *c.cmd.Temporal
	event, live := c.node.Events[id]
	if !live {
		var found bool
		event, found = c.node.PlannedEvents[id]
		if !found {
			return apiErrorf(404, "Event not found")
		}
	}
	previous := eventTemporal(event)
	if err := validateTemporal(previous, value); err != nil {
		return err
	}
	if event.Metadata == nil {
		event.Metadata = map[string]interface{}{}
	}
	if c.cmd.Title != "" {
		event.Metadata["title"] = c.cmd.Title
	}
	if c.cmd.Content != "" {
		event.Metadata["description"] = c.cmd.Content
	}
	value.Reopen = false
	var history []temporalTransition
	raw, _ := json.Marshal(event.Metadata[temporalHistoryKey])
	_ = json.Unmarshal(raw, &history)
	event.Metadata[temporalHistoryKey] = workMetadataValue(append(history, temporalTransition{At: time.Now().UTC().Format(time.RFC3339Nano), By: c.user, From: previous, To: value}))
	event.Metadata[temporalKey] = workMetadataValue(value)
	event.Status = core.EventPending
	if value.Status == "active" {
		event.Status = core.EventOngoing
	}
	if value.Type == "event" {
		event.Status = core.EventFinished
	}
	event.StartTime, event.EndTime = nil, nil
	if value.Start != "" {
		start, _ := temporalInstant(value.Start)
		event.StartTime = &start
	}
	if value.End != "" {
		end, _ := temporalInstant(value.End)
		event.EndTime = &end
	}
	event.ModifiedAt, event.ModifiedBy = time.Now().UTC(), c.user
	if value.Type == "event" || live {
		c.node.Events[id] = event
		delete(c.node.PlannedEvents, id)
	} else {
		c.node.PlannedEvents[id] = event
	}
	c.result = map[string]interface{}{"event_id": id, "owner_id": c.node.ID, "revision": workRevision(c.node)}
	return nil
}
