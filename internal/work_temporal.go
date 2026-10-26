// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"time"
)

const temporalKey = "momentum.temporal"
const temporalHistoryKey = "momentum.temporal_history"

type temporalInput struct {
	Type       string `json:"type"`
	Status     string `json:"status"`
	Start      string `json:"start,omitempty"`
	End        string `json:"end,omitempty"`
	OccurredAt string `json:"occurred_at,omitempty"`
	Outcome    string `json:"outcome,omitempty"`
	Reopen     bool   `json:"reopen,omitempty"`
}

type temporalTransition struct {
	At   string        `json:"at"`
	By   string        `json:"by"`
	From temporalInput `json:"from"`
	To   temporalInput `json:"to"`
}

func nodeTemporal(node *core.Node) temporalInput {
	var value temporalInput
	raw, _ := json.Marshal(node.Metadata[temporalKey])
	_ = json.Unmarshal(raw, &value)
	if value.Type != "" {
		return value
	}
	status, _ := node.Metadata["status"].(string)
	value.Type, value.Status = "intent", status
	if status == "planned" || status == "active" || status == "blocked" {
		value.Type = "action"
	}
	if status == "done" || status == "cancelled" {
		value.Type, value.Outcome = "event", "completed"
		if status == "cancelled" {
			value.Outcome = "failed"
		}
	}
	return value
}

func temporalInstant(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		parsed, err = time.Parse("2006-01-02", value)
	}
	return parsed, err
}

func validateTemporalSpan(value temporalInput) error {
	if value.Start == "" && value.End == "" {
		return nil
	}
	start, a := temporalInstant(value.Start)
	if a != nil {
		return apiErrorf(400, "Choose a valid planned start")
	}
	if value.End == "" {
		return nil
	}
	end, b := temporalInstant(value.End)
	if b != nil || !end.After(start) {
		return apiErrorf(400, "Choose an end after the start")
	}
	return nil
}

func validateTemporal(previous, value temporalInput) error {
	if !workStatus(value.Status) {
		return apiErrorf(400, "Unknown workflow state")
	}
	if previous.Type == "event" && value.Type != "event" && !value.Reopen {
		return apiErrorf(409, "Explicitly reopen this event first")
	}
	if err := validateTemporalSpan(value); err != nil {
		return err
	}
	switch value.Type {
	case "intent":
		if value.Status != "idea" || value.Start != "" {
			return apiErrorf(400, "A scheduled or started Intent is an Action")
		}
	case "action":
		if value.Status != "planned" && value.Status != "active" && value.Status != "blocked" {
			return apiErrorf(400, "Choose an Action workflow state")
		}
	case "event":
		if value.Outcome != "completed" && value.Outcome != "failed" {
			return apiErrorf(400, "Choose completed or failed")
		}
		if value.Status != "done" && value.Status != "cancelled" {
			return apiErrorf(400, "An Event needs a terminal workflow state")
		}
		if _, err := time.Parse(time.RFC3339, value.OccurredAt); err != nil {
			return apiErrorf(400, "Choose an occurrence time with a timezone")
		}
	default:
		return apiErrorf(400, "Choose Intent, Action or Event")
	}
	if value.Type != "event" && (value.Outcome != "" || value.OccurredAt != "") {
		return apiErrorf(400, "Only Events have an occurrence and outcome")
	}
	return nil
}

func applyTemporal(node *core.Node, user string, value temporalInput) {
	previous := nodeTemporal(node)
	var history []temporalTransition
	raw, _ := json.Marshal(node.Metadata[temporalHistoryKey])
	_ = json.Unmarshal(raw, &history)
	value.Reopen = false
	history = append(history, temporalTransition{At: time.Now().UTC().Format(time.RFC3339Nano), By: user, From: previous, To: value})
	node.Metadata[temporalKey], node.Metadata[temporalHistoryKey] = workMetadataValue(value), workMetadataValue(history)
	node.Metadata["status"] = value.Status
}

func (s *Server) workCommandTemporal(c *workCommandContext) error {
	if c.cmd.Temporal == nil {
		return apiErrorf(400, "Provide the temporal update")
	}
	if c.cmd.EventID != "" {
		return s.workLegacyTemporal(c)
	}
	if c.node.Kind == "category" || c.node.Kind == "workspace" || c.node.Kind == "collection" {
		return apiErrorf(400, "Choose a work item")
	}
	value := *c.cmd.Temporal
	if err := validateTemporal(nodeTemporal(c.node), value); err != nil {
		return err
	}
	if err := s.checkRequirements(c.node, value); err != nil {
		return err
	}
	applyTemporal(c.node, c.user, value)
	c.result = map[string]interface{}{"id": c.node.ID, "temporal": value, "revision": workRevision(c.node)}
	return nil
}
