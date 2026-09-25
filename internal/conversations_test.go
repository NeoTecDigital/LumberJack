// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"testing"
)

func conversationCall(t *testing.T, s *Server, token, method, path string, body interface{}, status int) map[string]interface{} {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := s.ApplicationCall(ApplicationRequest{Method: method, Target: path, Headers: map[string]string{"Authorization": "Bearer " + token}, Body: raw})
	if r.Status != status {
		t.Fatalf("%s %s: wanted %d got %d: %s", method, path, status, r.Status, r.Body)
	}
	if status != 200 {
		return nil
	}
	return decodeApplication(t, r)
}
func TestConversationMembershipHistoryAndUnread(t *testing.T) {
	// Proven red: POST /conversations wanted 200 got 404.
	s := setupTestForest(t)
	tokens := map[string]string{}
	for _, id := range []string{"admin", "bob", "eve"} {
		if id != "admin" {
			s.forest.Users = append(s.forest.Users, core.User{ID: id, Username: id, Permissions: []core.Permission{core.ReadPermission}})
		}
		token, _, err := s.mintApplicationSession(id)
		if err != nil {
			t.Fatal(err)
		}
		tokens[id] = token
	}
	created := conversationCall(t, s, tokens["admin"], "POST", "/conversations", map[string]interface{}{"kind": "group", "title": "Planning", "usernames": []string{"bob"}, "client_id": "create-group"}, 200)
	id := created["id"].(string)
	path := "/conversations/" + id
	conversationCall(t, s, tokens["admin"], "POST", path+"/messages", map[string]string{"content": "before joining", "client_id": "one"}, 200)
	conversationCall(t, s, tokens["bob"], "GET", path+"/messages", nil, 403)
	conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	conversationCall(t, s, tokens["eve"], "GET", path+"/messages", nil, 404)
	conversationCall(t, s, tokens["bob"], "POST", path+"/messages", map[string]string{"content": "hello", "client_id": "reply"}, 200)
	conversationCall(t, s, tokens["bob"], "POST", path+"/messages", map[string]string{"content": "hello", "client_id": "reply"}, 200)
	result := conversationCall(t, s, tokens["bob"], "GET", path+"/messages", nil, 200)
	if len(result["items"].([]interface{})) != 1 {
		t.Fatal("joining exposed prior history or retry duplicated a message")
	}
	conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "remove", "username": "admin"}, 403)
	conversationCall(t, s, tokens["admin"], "POST", path+"/membership", map[string]string{"action": "remove", "username": "bob"}, 200)
	conversationCall(t, s, tokens["bob"], "GET", path+"/messages", nil, 404)
}
