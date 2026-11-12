// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/core"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestAssetIndexBoundedAndPrivateProjection(t *testing.T) {
	s, user := feedTestServer(t)
	e := s.changeForest(func() error {
		s.forest.Attachments = map[string]core.Attachment{"z": {ID: "z", Name: "second", Data: []byte("secret-bytes")}, "a": {ID: "a", Name: "first"}}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	page, e := s.AssetsIndex(user, "", 0, 1)
	if e != nil || len(page.Items) != 1 || page.Items[0].ID != "a" || page.Complete || page.NextOffset == nil {
		t.Fatalf("page %+v %v", page, e)
	}
	raw, _ := json.Marshal(page)
	if strings.Contains(string(raw), "secret-bytes") || strings.Contains(string(raw), `"data"`) {
		t.Fatal("file bytes exposed")
	}
	if _, e = s.AssetsIndex(user, "", 0, 101); e == nil {
		t.Fatal("oversize page")
	}
	rec := httptest.NewRecorder()
	s.HandleAssetsIndex(rec, withUser(httptest.NewRequest("GET", "/assets?limit=101", nil), user))
	if rec.Code != 400 {
		t.Fatal("invalid limit accepted")
	}
	rec = httptest.NewRecorder()
	s.HandleAssetsIndex(rec, httptest.NewRequest("GET", "/assets", nil))
	if rec.Code != 401 {
		t.Fatal("anonymous assets")
	}
}
func TestAssetIndexCurrentAccessAndConversationFiles(t *testing.T) {
	s, user := feedTestServer(t)
	other := "foreign-principal"
	e := s.changeForest(func() error {
		s.forest.Conversations = map[string]*core.Conversation{"c": {ID: "c", Members: map[string]core.ConversationMember{user: {From: 2}}, Attachments: map[string]core.ConversationAttachment{"foreign": {ID: "foreign", UploadedBy: other}, "own": {ID: "own", UploadedBy: user}}, Messages: []core.ConversationMessage{{Sequence: 1, Attachments: []core.ConversationAttachmentRef{{ID: "foreign", Version: 1}}}}}}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	page, e := s.AssetsIndex(user, "", 0, 100)
	if e != nil || len(page.Items) != 1 || page.Items[0].ID != "own" {
		t.Fatalf("history file isolation %+v %v", page, e)
	}
	e = s.changeForest(func() error { delete(s.forest.Conversations["c"].Members, user); return nil })
	if e != nil {
		t.Fatal(e)
	}
	page, e = s.AssetsIndex(user, "", 0, 100)
	if e != nil || len(page.Items) != 0 {
		t.Fatal("former member asset metadata")
	}
	if _, e = s.AssetsIndex(other, "", 0, 100); e == nil {
		t.Fatal("foreign actor accepted")
	}
	if _, e = s.AssetsIndex(user, "missing/path", 0, 100); e == nil {
		t.Fatal("missing scope accepted")
	}
}

func TestAssetIndexRefusesOversizedWorkWithoutMetadata(t *testing.T) {
	for _, kind := range []string{"files", "denied", "entries", "messages", "refs", "conversations", "access_grants", "users", "node_users", "permissions", "edits", "edit_refs"} {
		t.Run(kind, func(t *testing.T) {
			s, user := feedTestServer(t)
			if err := s.changeForest(func() error {
				assetIndexOversizedFixture(s, user, kind)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if kind == "access_grants" {
				assetIndexAssertMaterializedGrants(t, s)
			}
			page, err := s.AssetsIndex(user, "", 0, 1)
			if err == nil || len(page.Items) != 0 || page.Total != 0 || page.Complete || page.NextOffset != nil {
				t.Fatalf("refusal leaked success: %+v %v", page, err)
			}
			rec := httptest.NewRecorder()
			s.HandleAssetsIndex(rec, withUser(httptest.NewRequest("GET", "/assets?limit=1", nil), user))
			if rec.Code != 503 || strings.Contains(rec.Body.String(), "hidden-secret") {
				t.Fatalf("refusal %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func assetIndexOversizedFixture(s *Server, user, kind string) {
	n := assetIndexWorkLimit + 1
	if assetIndexOversizedACLFixture(s, user, kind, n) {
		return
	}
	switch kind {
	case "files":
		s.forest.Attachments = make(map[string]core.Attachment, n)
		for i := 0; i < n; i++ {
			id := strconv.Itoa(i)
			s.forest.Attachments[id] = core.Attachment{ID: id, Name: "hidden-secret"}
		}
	case "denied":
		s.forest.Children = make(map[string]*core.Node, n)
		for i := 0; i < n; i++ {
			id := strconv.Itoa(i)
			s.forest.Children[id] = &core.Node{ID: id, Name: "hidden-secret"}
		}
	case "entries":
		s.forest.Entries = make([]core.Entry, n)
	case "conversations":
		s.forest.Conversations = make(map[string]*core.Conversation, n)
		for i := 0; i < n; i++ {
			s.forest.Conversations[strconv.Itoa(i)] = &core.Conversation{}
		}
	default:
		c := &core.Conversation{ID: "hidden-secret", Members: map[string]core.ConversationMember{user: {}}, Attachments: map[string]core.ConversationAttachment{"file": {ID: "file", UploadedBy: "other"}}}
		if kind == "messages" {
			c.Messages = make([]core.ConversationMessage, n)
		}
		if kind == "refs" {
			c.Messages = []core.ConversationMessage{{Sequence: 1, Attachments: make([]core.ConversationAttachmentRef, n)}}
		}
		if kind == "edits" {
			c.Messages = []core.ConversationMessage{{Sequence: 1, EditEvidence: make([]core.ConversationMessageEdit, n)}}
		}
		if kind == "edit_refs" {
			c.Messages = []core.ConversationMessage{{Sequence: 1, EditEvidence: []core.ConversationMessageEdit{{Attachments: make([]core.ConversationAttachmentRef, n)}}}}
		}
		s.forest.Conversations = map[string]*core.Conversation{"c": c}
	}
}

func TestAssetIndexSmallQueryPagingUnchanged(t *testing.T) {
	s, user := feedTestServer(t)
	if err := s.changeForest(func() error {
		s.forest.Attachments = map[string]core.Attachment{"b": {ID: "b"}, "a": {ID: "a"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	page, err := s.AssetsIndex(user, "", 1, 1)
	if err != nil || page.Total != 2 || !page.Complete || page.NextOffset != nil || len(page.Items) != 1 || page.Items[0].ID != "b" {
		t.Fatalf("last page %+v %v", page, err)
	}
}

func TestAssetIndexBudgetNeverExceedsCeiling(t *testing.T) {
	b := &assetIndexBudget{}
	if !b.take(assetIndexWorkLimit) || b.take(1) || b.used != assetIndexWorkLimit || b.err == nil {
		t.Fatal("unbounded budget")
	}
}

func assetIndexOversizedACLFixture(s *Server, user, kind string, n int) bool {
	child := &core.Node{ID: "hidden-secret", Name: "hidden-secret"}
	switch kind {
	case "access_grants":
		child.CreatedBy = user
		s.forest.Users = append(s.forest.Users, core.User{ID: "other", Username: "other"})
		s.forest.AccessPolicies = make(map[string]core.AccessGrant, n)
		for i := 0; i < n; i++ {
			id := "asset-budget-grant-" + strconv.Itoa(i)
			s.forest.AccessPolicies[id] = core.AccessGrant{ID: id, RootID: child.ID, GrantorID: user, RecipientID: "other", Permission: core.ReadPermission, Scope: "item"}
		}
	case "users":
		s.forest.Users = append(s.forest.Users, make([]core.User, n)...)
		return true
	case "node_users":
		child.Users = make([]core.User, n)
	case "permissions":
		child.Users = []core.User{{ID: user, Permissions: make([]core.Permission, n)}}
	default:
		return false
	}
	// The readable root contributes a row before the oversized child is visited.
	// The refusal must discard that partial projection, not publish it.
	s.forest.Attachments = map[string]core.Attachment{"partial": {ID: "partial", Name: "hidden-secret"}}
	s.forest.Children = map[string]*core.Node{child.ID: child}
	return true
}

func assetIndexAssertMaterializedGrants(t *testing.T, s *Server) {
	t.Helper()
	s.readForest(func() {
		child := s.forest.Children["hidden-secret"]
		if child == nil || len(child.AccessGrants) != assetIndexWorkLimit+1 {
			t.Fatal("durable policies did not materialize oversized ACL fixture")
		}
	})
}
