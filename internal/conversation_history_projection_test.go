// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "testing"

// Observed red 2026-09-21: caller history boundary absent: <nil>.
func TestConversationProjectsOnlyCallerHistoryBoundary(t *testing.T) {
	s, tokens := conversationFixture(t)
	created := conversationCall(t, s, tokens["alice"], "POST", "/conversations", map[string]interface{}{"kind": "group", "title": "History", "usernames": []string{"bob"}, "client_id": "history-projection"}, 200)
	path := "/conversations/" + created["id"].(string)
	conversationCall(t, s, tokens["alice"], "POST", path+"/messages", map[string]string{"content": "Before joining", "client_id": "before"}, 200)
	accepted := conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	if accepted["history_from"] != float64(1) {
		t.Fatalf("caller history boundary absent: %#v", accepted["history_from"])
	}
	for _, raw := range accepted["members"].([]interface{}) {
		if _, ok := raw.(map[string]interface{})["history_from"]; ok {
			t.Fatal("another member's private boundary was projected")
		}
	}
	conversationCall(t, s, tokens["alice"], "POST", path+"/messages", map[string]string{"content": "Previously visible", "client_id": "visible"}, 200)
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]string{"action": "remove", "username": "bob"}, 200)
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]string{"action": "invite", "username": "bob"}, 200)
	again := conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	if again["history_from"] != float64(2) {
		t.Fatalf("rejoined caller still advertises old boundary: %#v", again)
	}
	list := conversationCall(t, s, tokens["bob"], "GET", "/conversations", nil, 200)
	if list["items"].([]interface{})[0].(map[string]interface{})["history_from"] != float64(2) {
		t.Fatal("polling list omitted current caller's cutoff")
	}
}
