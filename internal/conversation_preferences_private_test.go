package internal

import (
	"github.com/NeoTecDigital/LumberJack/core"
	"testing"
)

func TestConversationPrivateBookmarksAndRefusal(t *testing.T) {
	s := setupTestForest(t)
	s.forest.Users = append(s.forest.Users, core.User{ID: "bob", Username: "bob", Permissions: []core.Permission{core.ReadPermission}})
	a, _, _ := s.mintApplicationSession("admin")
	b, _, _ := s.mintApplicationSession("bob")
	created := conversationCall(t, s, a, "POST", "/conversations", map[string]interface{}{"kind": "group", "title": "Fixture room", "usernames": []string{"bob"}, "client_id": "fixture-room"}, 200)
	path := "/conversations/" + created["id"].(string)
	old := conversationCall(t, s, a, "POST", path+"/messages", map[string]string{"content": "Fixture earlier", "client_id": "fixture-before"}, 200)
	conversationCall(t, s, b, "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	conversationCall(t, s, b, "PATCH", path+"/preferences", map[string]interface{}{"message_save": map[string]interface{}{"id": old["id"], "saved": true}}, 404)
	msg := conversationCall(t, s, a, "POST", path+"/messages", map[string]string{"content": "Fixture accessible", "client_id": "fixture-message"}, 200)
	prefs := conversationCall(t, s, b, "PATCH", path+"/preferences", map[string]interface{}{"saved": true, "refused": true, "muted": true, "archived": true, "message_save": map[string]interface{}{"id": msg["id"], "saved": true}}, 200)
	if prefs["saved"] != true || prefs["refused"] != true || prefs["saved_message_count"] != float64(1) || prefs["unread"] != float64(1) {
		t.Fatalf("wrong private flags: %v", prefs)
	}
	other := conversationCall(t, s, a, "PATCH", path+"/preferences", map[string]interface{}{}, 200)
	if other["saved"] == true || other["refused"] == true || other["saved_message_count"] != float64(0) {
		t.Fatal("preferences leaked across users")
	}
	raw, _ := encodeState(s.forest)
	restored, err := decodeState(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.forest = restored
	prefs = conversationCall(t, s, b, "PATCH", path+"/preferences", map[string]interface{}{"refused": false}, 200)
	if prefs["muted"] != true || prefs["archived"] != true || prefs["unread"] != float64(1) || prefs["saved_message_count"] != float64(1) {
		t.Fatal("restore changed prior preferences or history")
	}
	conversationCall(t, s, a, "POST", path+"/membership", map[string]string{"action": "remove", "username": "bob"}, 200)
	conversationCall(t, s, b, "PATCH", path+"/preferences", map[string]interface{}{"message_save": map[string]interface{}{"id": msg["id"], "saved": false}}, 404)
}
