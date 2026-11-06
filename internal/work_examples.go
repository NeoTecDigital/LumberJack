// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"time"
)

const exampleKey = "momentum.examples.v1"

type exampleReceipt struct {
	Version int      `json:"version"`
	ID      string   `json:"id"`
	Path    string   `json:"path"`
	Anchor  string   `json:"anchor"`
	Items   []string `json:"item_ids"`
}
type exampleSpec struct {
	title, kind, status, outcome string
	categories                   []string
	day                          int
}

func exampleSpecs() []exampleSpec {
	return []exampleSpec{
		{"Imagine a healthier routine", "intent", "idea", "", []string{"Health"}, 0},
		{"Explore a learning fund", "intent", "idea", "", []string{"Wealth"}, 0},
		{"Make room for connection", "intent", "idea", "", []string{"Love", "Happiness"}, 0},
		{"Enjoy an exercise walk", "action", "active", "", []string{"Health", "Happiness"}, 0},
		{"Review a budget outline", "action", "planned", "", []string{"Wealth"}, 1},
		{"Plan time with a friend", "action", "planned", "", []string{"Love"}, 2},
		{"Enjoyed a quiet reading break", "event", "done", "completed", []string{"Happiness"}, -1},
		{"Missed a stretching session", "event", "done", "failed", []string{"Health"}, -1},
	}
}

func (s *Server) exampleCategories(home *core.Node, user string) (map[string]*core.Node, error) {
	var ids map[string]string
	raw, _ := json.Marshal(home.Metadata[categoryIDs])
	_ = json.Unmarshal(raw, &ids)
	result := map[string]*core.Node{}
	for title, id := range ids {
		category := home.Children[id]
		if category == nil || category.Kind != "category" || !category.CheckPermission(user, core.ReadPermission) {
			continue
		}
		for _, account := range s.forest.Users {
			if account.ID != user && account.ID != SystemUserID && category.CheckPermission(account.ID, core.ReadPermission) {
				return nil, apiErrorf(409, "Examples require private categories; review category access first")
			}
		}
		result[title] = category
	}
	return result, nil
}

func (s *Server) seedExample(branch *core.Node, user string, spec exampleSpec, anchor time.Time, categories map[string]*core.Node) (string, error) {
	node, err := s.workChild(branch, spec.title, "action", user)
	if err != nil {
		return "", err
	}
	node.Metadata["momentum.example"] = true
	node.Metadata["description"] = "Editable example — illustrative only. No personal target or financial amount is set."
	node.Metadata["reminders_disabled"] = true
	node.Metadata["automatic_timer_disabled"] = true
	value := temporalInput{Type: spec.kind, Status: spec.status, Outcome: spec.outcome}
	start := anchor.AddDate(0, 0, spec.day)
	if spec.kind != "intent" {
		value.Start, value.End = start.Format(time.RFC3339), start.Add(30*time.Minute).Format(time.RFC3339)
	}
	if spec.kind == "event" {
		value.OccurredAt = value.End
	}
	applyTemporal(node, user, value)
	ids := []string{}
	for _, title := range spec.categories {
		category := categories[title]
		if category == nil {
			continue
		} // A removed default is respected, never recreated by examples.
		ids = append(ids, category.ID)
		// Newly private nodes and private categories cannot widen access or form a cycle.
		category.Children[node.ID] = node
		node.AddParent(category)
	}
	node.Metadata["category_ids"] = ids
	return node.ID, nil
}

func (s *Server) workCommandExamples(c *workCommandContext) error {
	home := c.node
	if c.cmd.ExampleVersion != 1 {
		return apiErrorf(400, "Choose example version 1")
	}
	if home.Metadata["personal_owner"] != c.user || !home.CheckPermission(c.user, core.AdminPermission) {
		return apiErrorf(403, "Examples belong to your private home")
	}
	if prior := home.Metadata[exampleKey]; prior != nil {
		var receipt exampleReceipt
		raw, _ := json.Marshal(prior)
		if json.Unmarshal(raw, &receipt) != nil || home.Children[receipt.ID] == nil {
			return apiErrorf(410, "The example branch was removed; it will not be reseeded")
		}
		c.result, c.changedPath = receipt, receipt.Path
		return nil
	}
	categories, err := s.exampleCategories(home, c.user)
	if err != nil {
		return err
	}
	branch, err := s.workChild(home, "Examples — editable sample data", "project", c.user)
	if err != nil {
		return err
	}
	branch.Metadata["momentum.example"] = true
	branch.Metadata["momentum.example_branch"] = true
	now := time.Now().UTC()
	anchor := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, time.UTC)
	receipt := exampleReceipt{Version: 1, ID: branch.ID, Path: c.cmd.Path + "/" + branch.Name, Anchor: anchor.Format(time.RFC3339), Items: []string{}}
	for _, spec := range exampleSpecs() {
		id, err := s.seedExample(branch, c.user, spec, anchor, categories)
		if err != nil {
			return err
		}
		receipt.Items = append(receipt.Items, id)
	}
	home.Metadata[exampleKey] = workMetadataValue(receipt)
	c.result, c.changedPath, c.mutationKind = receipt, receipt.Path, mutationNodeCreated
	return nil
}
