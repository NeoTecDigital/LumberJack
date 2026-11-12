// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"github.com/NeoTecDigital/LumberJack/core"
	"strings"
	"time"
)

func updateTemporal(node *core.Node, cmd WorkCommand) *temporalInput {
	if cmd.Temporal != nil {
		return cmd.Temporal
	}
	if nodeTemporal(node).Status == cmd.Status {
		return nil
	}
	value := nodeTemporal(node)
	value.Status = cmd.Status
	if cmd.Status == "done" || cmd.Status == "cancelled" {
		value.Type, value.Outcome, value.OccurredAt = "event", "completed", time.Now().UTC().Format(time.RFC3339Nano)
		if cmd.Status == "cancelled" {
			value.Outcome = "failed"
		}
	} else if cmd.Status == "idea" {
		value.Type = "intent"
	} else {
		value.Type = "action"
	}
	return &value
}

func (s *Server) workCommandUpdate(c *workCommandContext) error {
	node, cmd := c.node, c.cmd
	if strings.TrimSpace(cmd.Title) == "" || len(cmd.Title) > 200 {
		return apiErrorf(400, "Name your work (up to 200 characters)")
	}
	if !workKind(cmd.Kind) || !workStatus(cmd.Status) {
		return apiErrorf(400, "Unknown work kind or status")
	}
	if cmd.AssignedTo != "" && !node.CheckPermission(cmd.AssignedTo, core.ReadPermission) {
		return apiErrorf(400, "Assign work to one of its members")
	}
	value := updateTemporal(node, cmd)
	if value != nil {
		if value.Status != cmd.Status {
			return apiErrorf(400, "Temporal and workflow states must agree")
		}
		if err := validateTemporal(nodeTemporal(node), *value); err != nil {
			return err
		}
		if err := s.checkRequirements(node, *value); err != nil {
			return err
		}
	}
	if err := s.workCategoryPatch(node, c.user, cmd); err != nil {
		return err
	}
	if err := workDetails(node, cmd); err != nil {
		return err
	}
	if value != nil {
		applyTemporal(node, c.user, *value)
	}
	node.Kind = cmd.Kind
	node.Metadata["title"], node.Metadata["description"] = cmd.Title, cmd.Content
	node.Metadata["status"], node.Metadata["assigned_to"] = cmd.Status, cmd.AssignedTo
	return nil
}
