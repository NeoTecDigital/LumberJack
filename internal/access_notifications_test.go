// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// Observed red 2026-09-21: accepted grant did not queue exactly one notification.
func TestAccessNotificationOnlyForAcceptedExplicitRecipient(t *testing.T) {
	s, path := accessAuthorityFixture(t)
	node, _ := s.getNodeFromPath(path)
	s.forest.Subscriptions = map[string]map[string]bool{"manager": {node.ID: true}}
	s.correspondenceState().Pending = map[string]core.CorrespondenceChange{}
	request := map[string]interface{}{"action": "grant", "path": path, "username": "reader", "scope": "item", "permission": 0}
	preview := accessTestCall(t, s, "admin", "/access/preview", request, 200)
	request["revision"] = "stale"
	accessTestCall(t, s, "admin", "/access/apply", request, 409)
	if len(s.correspondenceState().Pending) != 0 {
		t.Fatal("preview or refusal queued a sharing notification")
	}
	request["revision"] = preview["revision"]
	applied := accessTestCall(t, s, "admin", "/access/apply", request, 200)
	accessTestCall(t, s, "admin", "/access/apply", request, 409)
	if len(s.correspondenceState().Pending) != 1 {
		t.Fatal("accepted grant did not queue exactly one notification")
	}
	for id, change := range s.correspondenceState().Pending {
		if change.Operation != "share" || len(change.Recipients) != 1 || change.Recipients[0] != "reader" {
			t.Fatalf("share broadcast beyond explicit recipient: %#v", change)
		}
		raw, _ := json.Marshal(map[string]string{"operation": "deliver", "id": id})
		if _, err := s.ApplicationHub(raw); err != nil {
			t.Fatal(err)
		}
	}
	notifications := func() int {
		rec := httptest.NewRecorder()
		s.handleApplicationNotifications(rec, withUser(httptest.NewRequest("GET", "/notifications", nil), "reader"))
		var body struct {
			Items []interface{} `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return len(body.Items)
	}
	if notifications() != 1 {
		t.Fatal("explicit recipient did not receive sharing alert")
	}
	reviewedAccessRevoke(t, s, "admin", path, applied["grant_id"].(string))
	if notifications() != 0 {
		t.Fatal("revocation exposed private title or content")
	}
	for _, change := range s.correspondenceState().Pending {
		if len(change.Recipients) > 0 {
			t.Fatal("revoked recipient or observer received sharing content")
		}
	}
}
