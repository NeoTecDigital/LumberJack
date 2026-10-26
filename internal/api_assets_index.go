// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
)

type AssetIndexItem struct {
	ID            string      `json:"id"`
	OwnershipKind string      `json:"ownership_kind"`
	OwnerID       string      `json:"owner_id"`
	ParentID      string      `json:"parent_id"`
	Path          string      `json:"path,omitempty"`
	EventID       string      `json:"event_id,omitempty"`
	EntryID       string      `json:"entry_id,omitempty"`
	Version       uint64      `json:"version,omitempty"`
	File          interface{} `json:"file"`
}
type AssetIndexPage struct {
	Items      []AssetIndexItem `json:"items"`
	Offset     int              `json:"offset"`
	Limit      int              `json:"limit"`
	NextOffset *int             `json:"next_offset"`
	Complete   bool             `json:"complete"`
	Total      int              `json:"total"`
	Coverage   string           `json:"coverage"`
}

func (s *Server) HandleAssetsIndex(w http.ResponseWriter, r *http.Request) {
	user, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "Sign in required", 401)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method unavailable", 405)
		return
	}
	limit, e := assetPageInt(r.URL.Query().Get("limit"), 100, 100)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	offset, e := assetPageInt(r.URL.Query().Get("offset"), 0, 1000000)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	if limit == 0 {
		http.Error(w, "Limit must be positive", 400)
		return
	}
	page, e := s.AssetsIndex(user, r.URL.Query().Get("path"), offset, limit)
	if e != nil {
		writeAPIError(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(page)
}
func assetPageInt(raw string, def, max int) (int, error) {
	if raw == "" {
		return def, nil
	}
	n, e := strconv.Atoi(raw)
	if e != nil || n < 0 || n > max {
		return 0, apiErrorf(400, "Invalid assets page")
	}
	return n, nil
}
func (s *Server) AssetsIndex(user, path string, offset, limit int) (AssetIndexPage, error) {
	page := AssetIndexPage{Items: []AssetIndexItem{}, Offset: offset, Limit: limit, Coverage: "current_access_metadata"}
	if offset < 0 || limit < 1 || limit > 100 {
		return page, apiErrorf(400, "Invalid assets page")
	}
	var failure error
	s.readForest(func() {
		b := &assetIndexBudget{}
		if !b.account(s.forest, user) {
			if b.err != nil {
				failure = b.err
				return
			}
			failure = apiErrorf(401, "Account unavailable")
			return
		}
		root := s.forest
		rootPath := s.forest.Name
		if path != "" {
			var e error
			root, e = s.assetScope(path, b)
			if e != nil || !b.readable(root, user) {
				failure = apiErrorf(404, "Asset scope unavailable")
				if b.err != nil {
					failure = b.err
				}
				return
			}
			rootPath = s.canonicalPath(path)
		}
		items := s.nodeAssetItems(root, rootPath, user, b)
		if path == "" {
			items = append(items, s.conversationAssetItems(user, b)...)
		}
		if b.err != nil {
			failure = b.err
			return
		}
		sortAssetItems(items)
		page = assetIndexSlice(page, items)
	})
	return page, failure
}
func sortAssetItems(items []AssetIndexItem) {
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.OwnershipKind != b.OwnershipKind {
			return a.OwnershipKind < b.OwnershipKind
		}
		if a.OwnerID != b.OwnerID {
			return a.OwnerID < b.OwnerID
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.EventID != b.EventID {
			return a.EventID < b.EventID
		}
		return a.EntryID < b.EntryID
	})
}

func assetIndexSlice(page AssetIndexPage, items []AssetIndexItem) AssetIndexPage {
	page.Total = len(items)
	start := page.Offset
	if start > len(items) {
		start = len(items)
	}
	end := start + page.Limit
	if end > len(items) {
		end = len(items)
	}
	page.Items = items[start:end]
	page.Complete = end == len(items)
	if !page.Complete {
		page.NextOffset = &end
	}
	return page
}
