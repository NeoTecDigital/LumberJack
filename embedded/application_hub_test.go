// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
)

// noticeExtension enqueues a Direct notice through Tx.Enqueue, which is how an extension feeds the
// outbox now that no product does.
type noticeExtension struct{ host *extension.Host }

func (e noticeExtension) Spec() extension.Spec { return extension.Spec{Name: "notice"} }

func (e noticeExtension) Attach(host extension.Host) (extension.Instance, error) {
	*e.host = host
	return e, nil
}

func (e noticeExtension) Close(context.Context) error { return nil }

func TestApplicationHubSurvivesRestartAndFiltersRevocation(t *testing.T) {
	// Observed before fixture repair: password-only login panicked with
	// "interface conversion: interface {} is nil, not string" (FAIL, 0.084s).
	isolatedApplicationSecurity(t)
	cfg := embeddedConfig(t)
	password, key := applicationCredential(), applicationCredential()
	var h *Handle
	var host extension.Host
	open := func() {
		var err error
		h, err = OpenWith(cfg, "hub", noticeExtension{host: &host})
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
		return applicationLogin(t, h, username, password)
	}
	token := login("operator")
	call("POST", "/users/create", token, map[string]string{"username": "bob", "password": password, "email": "bob@example.test"})
	bob := login("bob")
	// The record is private to its creator, as one made by a product is: the forest's user inventory
	// is not an invitation to it, so the grant below is the only way bob can read it.
	operatorID, bobID := call("GET", "/principal", token, nil)["id"].(string), call("GET", "/principal", bob, nil)["id"].(string)
	nodeID, path := privateRecord(t, host, operatorID, "shared-idea")
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
	if len(pending) != 1 {
		t.Fatalf("want the share, got %s", before)
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
	if _, err := host.Change(context.Background(), extension.WriteOp{Key: "queued-before-revoke"}, func(tx extension.Tx) error {
		return tx.Enqueue(core.OutboxChange{ID: "queued-before-revoke", PinID: nodeID, Path: path, Operation: "update", Recipients: []string{bobID}, Direct: true})
	}); err != nil {
		t.Fatal(err)
	}
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

// privateRecord makes a child of the root that only its creator can read, through the extension's
// Host, and answers its id and path.
func privateRecord(t *testing.T, host extension.Host, creator, name string) (string, string) {
	t.Helper()
	var id, rootName string
	if _, err := host.Change(context.Background(), extension.WriteOp{Key: "record:" + name}, func(tx extension.Tx) error {
		root := tx.Root()
		node := core.NewNode(core.BranchNode, name)
		node.Parents = map[string]string{root.ID: root.Name}
		node.CreatedBy = creator
		node.Users = []core.User{{ID: creator, Permissions: []core.Permission{core.AdminPermission}}}
		root.Children[node.ID] = node
		id, rootName = node.ID, root.Name
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return id, rootName + "/" + name
}
