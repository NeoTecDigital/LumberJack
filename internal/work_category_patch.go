// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"strings"
)

// Category references are authorized records, not global names or access grants.
func (s *Server) workCategoryPatch(node *core.Node, user string, cmd workCommand) error {
	if cmd.CategoryIDs == nil && cmd.Categories == nil {
		return nil
	}
	home := s.forest.ChildNamed("personal-" + user)
	if home == nil || home.Metadata["personal_owner"] != user {
		return apiErrorf(409, "Initialize your private workspace first")
	}
	ids := []string{}
	if cmd.CategoryIDs != nil {
		ids = append(ids, (*cmd.CategoryIDs)...)
	}
	if len(ids) > 10 || cmd.Categories != nil && len(*cmd.Categories) > 10 {
		return apiErrorf(400, "Choose up to ten categories")
	}
	for _, id := range ids {
		valid := false
		_ = s.walkScope("", nil, func(at visit) {
			if at.node.ID == id && at.node.Kind == "category" && at.node.CheckPermission(user, core.ReadPermission) {
				valid = true
			}
		})
		if !valid {
			return apiErrorf(404, "Category not found")
		}
	}
	if cmd.Categories != nil {
		for _, title := range *cmd.Categories {
			id, err := s.resolveCategoryLabel(home, user, title)
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
	}
	unique := []string{}
	seen := map[string]bool{}
	for _, id := range ids {
		if !seen[id] {
			unique = append(unique, id)
			seen[id] = true
		}
	}
	if len(unique) > 10 {
		return apiErrorf(400, "Choose up to ten categories")
	}
	node.Metadata["category_ids"] = unique
	return nil
}

func (s *Server) resolveCategoryLabel(home *core.Node, user, title string) (string, error) {
	title = strings.TrimSpace(title)
	if title == "" || len(title) > 160 {
		return "", apiErrorf(400, "Name a category")
	}
	for _, child := range home.Children {
		name, _ := child.Metadata["title"].(string)
		if child.Kind == "category" && strings.EqualFold(name, title) && child.CheckPermission(user, core.ReadPermission) {
			return child.ID, nil
		}
	}
	child, err := s.workChild(home, title, "category", user)
	if err != nil {
		return "", err
	}
	return child.ID, nil
}
