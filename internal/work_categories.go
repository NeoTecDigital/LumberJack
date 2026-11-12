// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/core"
	"sort"
	"strings"
)

const categoryMarker = "momentum.default_categories"
const categoryIDs = "momentum.default_category_ids"

var defaultCategoryTitles = []string{"Health", "Wealth", "Love", "Happiness"}

// Runs within the workspace transaction: records, receipt and marker commit together.
func (s *Server) workDefaultCategories(home *core.Node, user string) (interface{}, error) {
	if home.Metadata["personal_owner"] != user || !home.CheckPermission(user, core.AdminPermission) {
		return nil, apiErrorf(403, "Default categories require your private home")
	}
	ids := map[string]string{}
	complete := fmtCategoryVersion(home.Metadata[categoryMarker]) >= 1
	for _, title := range defaultCategoryTitles {
		id := s.retainedCategory(home, user, title)
		if id == "" && !complete {
			child, err := s.workChild(home, title, "category", user)
			if err != nil {
				return nil, err
			}
			id = child.ID
		}
		if id != "" {
			ids[title] = id
		}
	}
	if home.Metadata[categoryIDs] == nil {
		home.Metadata[categoryIDs] = ids
	}
	home.Metadata[categoryMarker] = 1
	return map[string]interface{}{"id": home.ID, "category_ids": home.Metadata[categoryIDs]}, nil
}

func fmtCategoryVersion(value interface{}) float64 {
	raw, _ := json.Marshal(value)
	var n float64
	_ = json.Unmarshal(raw, &n)
	return n
}

// Legacy frontend receipts survive renaming and a partial setup; never global name merging.
func (s *Server) retainedCategory(home *core.Node, user, title string) string {
	identity := user + ":momentum-default-v1:" + home.ID + ":" + strings.ToLower(title)
	if receipt, ok := home.CommandReceipts[identity]; ok {
		raw, _ := json.Marshal(receipt)
		var prior struct {
			Result struct {
				Result struct {
					ID string `json:"id"`
				} `json:"result"`
			} `json:"result"`
		}
		if json.Unmarshal(raw, &prior) == nil && prior.Result.Result.ID != "" {
			return prior.Result.Result.ID
		}
	}
	matches := []string{}
	for _, node := range home.Children {
		name, _ := node.Metadata["title"].(string)
		if name == "" {
			name = node.Name
		}
		if node.Kind == "category" && strings.EqualFold(strings.TrimSpace(name), title) && node.CheckPermission(user, core.ReadPermission) {
			matches = append(matches, node.ID)
		}
	}
	sort.Strings(matches)
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}
