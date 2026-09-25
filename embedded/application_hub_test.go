// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"encoding/json"
	"testing"
)

func TestApplicationHubSurvivesRestartAndFiltersRevocation(t *testing.T) {
	// Observed before fixture repair: password-only login panicked with
	// "interface conversion: interface {} is nil, not string" (FAIL, 0.084s).
	isolatedApplicationSecurity(t)
	cfg := embeddedConfig(t)
	password, key := applicationCredential(), applicationCredential()
	var h *Handle
	open := func() {
		var err error
		h, err = Open(cfg, "hub")
		if err != nil {
			t.Fatal(err)
		}
		if err = h.ConfigureApplication("operator", password, key); err != nil {
			t.Fatal(err)
		}
	}
	open()
	defer func() { h.Close() }()
	call := func(method, target, token string, input interface{}) map[string]interface{} {
		t.Helper()
		body, _ := json.Marshal(input)
		answer, err := h.ApplicationCall(ApplicationRequest{Method: method, Target: target, Headers: map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}, Body: body})
		if err != nil || answer.Status != 200 {
			t.Fatalf("%s %s: %v %d %s", method, target, err, answer.Status, answer.Body)
		}
		var result map[string]interface{}
		if len(answer.Body) == 0 {
			return map[string]interface{}{}
		}
		if err = json.Unmarshal(answer.Body, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	hub := func(operation, id string) json.RawMessage {
		t.Helper()
		request, _ := json.Marshal(map[string]string{"operation": operation, "id": id})
		result, err := h.ApplicationHub(request)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	login := func(username string) string {
		return applicationMFALogin(t, h, username, password)
	}
	token := login("operator")
	call("POST", "/users/create", token, map[string]string{"username": "bob", "password": password, "email": "bob@example.test"})
	bob := login("bob")
	workspace := call("GET", "/workspace", token, nil)
	root := workspace["nodes"].([]interface{})[0].(map[string]interface{})["path"].(string)
	create := map[string]interface{}{"command": "create", "path": root, "client_id": "create", "title": "Shared idea", "kind": "idea"}
	created := call("POST", "/workspace/commands", token, create)
	path := created["path"].(string)
	// Replaying an acknowledged command does not queue a second delivery.
	call("POST", "/workspace/commands", token, create)
	share := map[string]interface{}{"action": "grant", "path": path, "username": "bob", "permission": 1, "scope": "item"}
	share["revision"] = call("POST", "/access/preview", token, share)["revision"]
	grant := call("POST", "/access/apply", token, share)["grant_id"]
	before := hub("pending", "")
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	open()
	if after := hub("pending", ""); string(before) != string(after) {
		t.Fatalf("outbox changed on restart: %s -> %s", before, after)
	}
	var pending []map[string]interface{}
	json.Unmarshal(before, &pending)
	if len(pending) != 2 {
		t.Fatalf("want create and share, got %s", before)
	}
	for _, item := range pending {
		hub("deliver", item["id"].(string))
		hub("deliver", item["id"].(string))
	}
	items := call("GET", "/notifications", bob, nil)["items"].([]interface{})
	if len(items) != 1 {
		t.Fatalf("want one share notification, got %#v", items)
	}
	id := items[0].(map[string]interface{})["id"].(string)
	call("POST", "/notifications", bob, map[string]string{"id": id})
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	open()
	items = call("GET", "/notifications", bob, nil)["items"].([]interface{})
	if items[0].(map[string]interface{})["read_at"] == "" {
		t.Fatal("read acknowledgment was lost")
	}
	call("POST", "/workspace/commands", token, map[string]interface{}{"command": "log", "path": path, "client_id": "queued-before-revoke", "content": "Private update"})
	revoke := map[string]interface{}{"action": "revoke", "path": path, "grant_id": grant}
	revoke["revision"] = call("POST", "/access/preview", token, revoke)["revision"]
	call("POST", "/access/apply", token, revoke)
	json.Unmarshal(hub("pending", ""), &pending)
	for _, item := range pending {
		hub("deliver", item["id"].(string))
	}
	if items := call("GET", "/notifications", bob, nil)["items"].([]interface{}); len(items) != 0 {
		t.Fatalf("revoked inbox leaked: %#v", items)
	}
	request := ApplicationRequest{Method: "POST", Target: "/_hub/deliver", Headers: map[string]string{"Authorization": "Bearer " + bob}}
	answer, _ := h.ApplicationCall(request)
	if answer.Status < 400 {
		t.Fatal("HTTP reached trusted hub capability")
	}
}
