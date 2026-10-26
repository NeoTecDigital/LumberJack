// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"math"
	"strings"
)

func workEditorDetails(node *core.Node, cmd WorkCommand) error {
	if cmd.Progress != nil {
		if math.IsNaN(*cmd.Progress) || math.IsInf(*cmd.Progress, 0) || *cmd.Progress < 0 || *cmd.Progress > 100 {
			return apiErrorf(400, "Progress must be from 0 to 100")
		}
		node.Metadata["progress"] = *cmd.Progress
	}
	if cmd.Priority != nil {
		allowed := map[string]bool{"": true, "low": true, "normal": true, "medium": true, "high": true, "urgent": true}
		if !allowed[*cmd.Priority] {
			return apiErrorf(400, "Choose a known priority")
		}
		node.Metadata["priority"] = *cmd.Priority
	}
	if cmd.Tags != nil {
		if len(*cmd.Tags) > 10 {
			return apiErrorf(400, "Choose at most ten tags")
		}
		for _, tag := range *cmd.Tags {
			if strings.TrimSpace(tag) == "" || len(tag) > 80 {
				return apiErrorf(400, "Use nonempty tags up to 80 characters")
			}
		}
		node.Metadata["tags"] = *cmd.Tags
	}
	return nil
}
