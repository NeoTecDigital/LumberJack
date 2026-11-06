// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import "strings"

func (s *Server) workCommandCreate(c *workCommandContext) error {
	cmd := c.cmd
	if strings.TrimSpace(cmd.Title) == "" || len(cmd.Title) > 200 {
		return apiErrorf(400, "Name your work (up to 200 characters)")
	}
	if !workKind(cmd.Kind) {
		return apiErrorf(400, "Choose a supported record kind")
	}
	child, err := s.workChild(c.node, cmd.Title, cmd.Kind, c.user)
	if err != nil {
		return err
	}
	child.Metadata["description"] = cmd.Content
	if cmd.Required {
		if c.node.Kind != "goal" && c.node.Kind != "action" && c.node.Kind != "project" {
			return apiErrorf(400, "A required step belongs within a goal, action or project")
		}
		child.Metadata["momentum.required_for"] = c.node.ID
	}
	if err = s.workCategoryPatch(child, c.user, cmd); err != nil {
		return err
	}
	if err = workDetails(child, cmd); err != nil {
		return err
	}
	if cmd.Temporal != nil {
		if err = validateTemporal(nodeTemporal(child), *cmd.Temporal); err != nil {
			return err
		}
		applyTemporal(child, c.user, *cmd.Temporal)
	}
	c.changedPath = s.canonicalPath(cmd.Path) + "/" + child.Name
	c.result = map[string]interface{}{"id": child.ID, "path": c.changedPath}
	c.mutationKind = mutationNodeCreated
	return nil
}
