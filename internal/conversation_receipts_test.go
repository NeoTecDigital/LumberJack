// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func TestConversationDirectMessageReuseRetainsEachReceipt(t *testing.T) {
	s, tokens := conversationFixture(t)
	first := map[string]interface{}{"kind": "dm", "usernames": []string{"bob"}, "client_id": "first"}
	second := map[string]interface{}{"kind": "dm", "usernames": []string{"bob"}, "client_id": "second"}
	created := conversationCall(t, s, tokens["alice"], "POST", "/conversations", first, 200)
	reused := conversationCall(t, s, tokens["alice"], "POST", "/conversations", second, 200)
	if created["id"] != reused["id"] || len(s.forest.Conversations) != 1 {
		t.Fatal("direct-message reuse created a duplicate")
	}
	conversationCall(t, s, tokens["alice"], "POST", "/conversations", map[string]interface{}{"kind": "dm", "usernames": []string{"eve"}, "client_id": "second"}, 409)
	// Round-trip the actual flat state codec; receipt authority must survive a
	// restart and not depend on a process-only idempotency map.
	data, err := encodeState(s.forest)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodeState(data)
	if err != nil {
		t.Fatal(err)
	}
	s.forest = restored
	retried := conversationCall(t, s, tokens["alice"], "POST", "/conversations", second, 200)
	if retried["id"] != created["id"] {
		t.Fatal("restart lost the alternate create receipt")
	}
	path := "/conversations/" + created["id"].(string)
	conversationCall(t, s, tokens["alice"], "POST", path+"/messages", map[string]string{"client_id": "hello", "content": "An initial direct message"}, 200)
	conversationCall(t, s, tokens["bob"], "POST", "/conversations", map[string]interface{}{"kind": "dm", "usernames": []string{"alice"}, "client_id": "pending"}, 403)
	conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	page := conversationCall(t, s, tokens["bob"], "GET", path+"/messages", nil, 200)
	if len(page["items"].([]interface{})) != 1 {
		t.Fatal("accepted DM hid the message addressed to its initial recipient")
	}
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]string{"action": "transfer", "username": "bob"}, 200)
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]string{"action": "leave"}, 200)
	conversationCall(t, s, tokens["alice"], "POST", "/conversations", second, 404)
}

func TestConversationProjectAssociationDoesNotGrantProjectAccess(t *testing.T) {
	s, tokens := conversationFixture(t)
	project := core.NewNode(core.BranchNode, "private-project")
	project.ID = "private-project"
	project.Users = []core.User{{ID: "alice", Permissions: []core.Permission{core.AdminPermission}}}
	s.forest.AddChild(project)
	request := map[string]interface{}{"kind": "channel", "title": "Project discussion", "project_path": "root/private-project", "usernames": []string{"bob"}, "client_id": "channel"}
	created := conversationCall(t, s, tokens["alice"], "POST", "/conversations", request, 200)
	path := "/conversations/" + created["id"].(string)
	conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	if project.CheckPermission("bob", core.ReadPermission) {
		t.Fatal("channel invitation granted resource access")
	}
	conversationCall(t, s, tokens["admin"], "GET", path+"/messages", nil, 404)
	request["client_id"] = "cannot-create"
	request["usernames"] = []string{"alice"}
	conversationCall(t, s, tokens["bob"], "POST", "/conversations", request, 403)
}

func TestConversationLegacyHistoryFlagAndRequestValidation(t *testing.T) {
	var member core.ConversationMember
	if err := json.Unmarshal([]byte(`{"invited":true,"from":18446744073709551615}`), &member); err != nil {
		t.Fatal(err)
	}
	if !member.IncludeHistory || member.From != 0 {
		t.Fatal("legacy invitation sentinel was not normalized into an explicit flag")
	}
	s, tokens := conversationFixture(t)
	created := conversationCall(t, s, tokens["alice"], "POST", "/conversations", map[string]interface{}{"kind": "group", "title": "Private", "usernames": []string{"bob"}, "client_id": "validate"}, 200)
	path := "/conversations/" + created["id"].(string)
	before, _ := json.Marshal(s.forest.Conversations)
	conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]interface{}{"action": "accept", "include_history": true}, 400)
	conversationCall(t, s, tokens["bob"], "PATCH", path+"/preferences", map[string]interface{}{"read_through": 0}, 403)
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]interface{}{"action": "invite", "username": "eve", "content": "unexpected message"}, 400)
	response := s.ApplicationCall(ApplicationRequest{Method: "POST", Target: path + "/membership", Headers: map[string]string{"Authorization": "Bearer " + tokens["alice"]}, Body: []byte(`{"action":"invite","username":"eve"} {"action":"leave"}`)})
	if response.Status != 400 {
		t.Fatal("trailing JSON was silently ignored")
	}
	after, _ := json.Marshal(s.forest.Conversations)
	if string(before) != string(after) {
		t.Fatal("invalid request changed membership before complete validation")
	}
}
