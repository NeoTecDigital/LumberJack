// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func conversationListed(t *testing.T, s *Server, token, id string) map[string]interface{} {
	t.Helper()
	list := conversationCall(t, s, token, "GET", "/conversations", nil, 200)
	for _, item := range list["items"].([]interface{}) {
		row := item.(map[string]interface{})
		if row["id"] == id {
			return row
		}
	}
	t.Fatal("conversation missing from participant list")
	return nil
}

func TestConversationUnreadHistoryPagingAndExplicitSharing(t *testing.T) {
	s, tokens := conversationFixture(t)
	made := conversationCall(t, s, tokens["alice"], "POST", "/conversations", map[string]interface{}{"kind": "group", "title": "Planning", "usernames": []string{"bob"}, "client_id": "pages"}, 200)
	id := made["id"].(string)
	path := "/conversations/" + id
	send := func(user, client, content string) {
		conversationCall(t, s, tokens[user], "POST", path+"/messages", map[string]string{"client_id": client, "content": content}, 200)
	}
	send("alice", "history", "before joining")
	invitation := conversationListed(t, s, tokens["bob"], id)
	if invitation["last_message"] != nil || invitation["unread"] != float64(0) {
		t.Fatal("pending invitation exposed message preview or unread history")
	}
	conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	send("alice", "new", "new message")
	send("bob", "reply", "reply")
	bob := conversationListed(t, s, tokens["bob"], id)
	alice := conversationListed(t, s, tokens["alice"], id)
	if bob["unread"] != float64(1) || alice["unread"] != float64(1) {
		t.Fatal("unread includes old history or the viewer's own message")
	}
	read := conversationCall(t, s, tokens["bob"], "PATCH", path+"/preferences", map[string]interface{}{"read_through": 3, "muted": true, "archived": true}, 200)
	if read["unread"] != float64(0) || read["muted"] != true || read["archived"] != true {
		t.Fatal("read or conversation preferences were not saved")
	}
	alice = conversationListed(t, s, tokens["alice"], id)
	if alice["muted"] != false || alice["archived"] != false || alice["unread"] != float64(1) {
		t.Fatal("one participant's preferences changed another participant")
	}
	unread := conversationCall(t, s, tokens["bob"], "PATCH", path+"/preferences", map[string]interface{}{"read_through": 0}, 200)
	if unread["unread"] != float64(1) {
		t.Fatal("mark unread restored inaccessible history")
	}
	before, _ := json.Marshal(s.forest.Conversations[id])
	conversationCall(t, s, tokens["bob"], "PATCH", path+"/preferences", map[string]interface{}{"read_through": 999, "muted": false}, 400)
	after, _ := json.Marshal(s.forest.Conversations[id])
	if string(before) != string(after) {
		t.Fatal("invalid read cursor partially changed preferences")
	}
	// Seed a large archive directly; message send/retry is exercised above and in
	// membership tests. Pagination must exclude the exact From boundary throughout.
	c := s.forest.Conversations[id]
	for seq := 4; seq <= 125; seq++ {
		c.Messages = append(c.Messages, core.ConversationMessage{ID: fmt.Sprintf("%s:%d", id, seq), Sequence: uint64(seq), AuthorID: "alice", Content: "archive", At: "2026-09-21T00:00:00Z", ClientID: fmt.Sprintf("seed-%d", seq)})
	}
	page := conversationCall(t, s, tokens["bob"], "GET", path+"/messages", nil, 200)
	if len(page["items"].([]interface{})) != 50 || page["next_before"] != float64(76) {
		t.Fatal("first history page or cursor incorrect")
	}
	page = conversationCall(t, s, tokens["bob"], "GET", path+"/messages?before=76", nil, 200)
	if len(page["items"].([]interface{})) != 50 || page["next_before"] != float64(26) {
		t.Fatal("second history page or cursor incorrect")
	}
	page = conversationCall(t, s, tokens["bob"], "GET", path+"/messages?before=26", nil, 200)
	items := page["items"].([]interface{})
	if len(items) != 24 || items[0].(map[string]interface{})["sequence"] != float64(2) || page["next_before"] != nil {
		t.Fatal("oldest page crossed joined-history boundary")
	}
	page = conversationCall(t, s, tokens["bob"], "GET", path+"/messages?before=2", nil, 200)
	if len(page["items"].([]interface{})) != 0 {
		t.Fatal("an older cursor exposed excluded history")
	}
	conversationCall(t, s, tokens["bob"], "GET", path+"/messages?before=0", nil, 400)
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]interface{}{"action": "invite", "username": "eve", "include_history": true}, 200)
	conversationCall(t, s, tokens["eve"], "GET", path+"/messages", nil, 403)
	conversationCall(t, s, tokens["eve"], "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	page = conversationCall(t, s, tokens["eve"], "GET", path+"/messages?before=2", nil, 200)
	if len(page["items"].([]interface{})) != 1 || s.forest.Conversations[id].Members["eve"].From != 0 {
		t.Fatal("explicit history sharing did not include older messages")
	}
}

func TestConversationIsolationAndAtomicMembershipFailures(t *testing.T) {
	s, tokens := conversationFixture(t)
	made := conversationCall(t, s, tokens["alice"], "POST", "/conversations", map[string]interface{}{"kind": "group", "title": "Private", "usernames": []string{"bob"}, "client_id": "private"}, 200)
	id := made["id"].(string)
	path := "/conversations/" + id
	for _, user := range []string{"admin", "eve"} {
		list := conversationCall(t, s, tokens[user], "GET", "/conversations", nil, 200)
		if len(list["items"].([]interface{})) != 0 {
			t.Fatal("administrator or outsider saw private conversation")
		}
		conversationCall(t, s, tokens[user], "GET", path+"/messages", nil, 404)
		conversationCall(t, s, tokens[user], "POST", path+"/messages", map[string]string{"client_id": "intrusion", "content": "no"}, 404)
		conversationCall(t, s, tokens[user], "POST", path+"/membership", map[string]string{"action": "accept"}, 404)
		conversationCall(t, s, tokens[user], "PATCH", path+"/preferences", map[string]bool{"muted": true}, 404)
	}
	conversationCall(t, s, tokens["bob"], "POST", path+"/messages", map[string]string{"client_id": "pending", "content": "no"}, 403)
	original, _ := json.Marshal(s.forest.Conversations[id])
	for _, invalid := range []map[string]interface{}{{"action": "transfer", "username": "bob"}, {"action": "invite", "username": "missing"}, {"action": "remove", "username": "alice"}, {"action": "leave"}} {
		status := 400
		if invalid["username"] == "missing" {
			status = 404
		}
		if invalid["action"] == "remove" || invalid["action"] == "leave" {
			status = 409
		}
		conversationCall(t, s, tokens["alice"], "POST", path+"/membership", invalid, status)
		current, _ := json.Marshal(s.forest.Conversations[id])
		if string(current) != string(original) {
			t.Fatal("failed membership validation changed persisted state")
		}
	}
	conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]string{"action": "remove", "username": "bob"}, 200)
	conversationCall(t, s, tokens["bob"], "PATCH", path+"/preferences", map[string]bool{"muted": true}, 404)
	conversationCall(t, s, tokens["bob"], "POST", path+"/messages", map[string]string{"client_id": "removed", "content": "no"}, 404)
	conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "accept"}, 404)
}

func TestConversationMessageRetryCannotCrossRejoinHistoryBoundary(t *testing.T) {
	// Observed red 2026-09-21: a retry after rejoining returned the excluded
	// sequence-1 message with 200, where the new membership required 409.
	s, tokens := conversationFixture(t)
	made := conversationCall(t, s, tokens["alice"], "POST", "/conversations", map[string]interface{}{"kind": "group", "title": "Planning", "usernames": []string{"bob"}, "client_id": "rejoin"}, 200)
	path := "/conversations/" + made["id"].(string)
	conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	message := map[string]string{"client_id": "old-message", "content": "old membership"}
	conversationCall(t, s, tokens["bob"], "POST", path+"/messages", message, 200)
	conversationCall(t, s, tokens["bob"], "POST", path+"/messages", map[string]string{"client_id": "old-message", "content": "changed"}, 409)
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]string{"action": "remove", "username": "bob"}, 200)
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]string{"action": "invite", "username": "bob"}, 200)
	conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	conversationCall(t, s, tokens["bob"], "POST", path+"/messages", message, 409)
}
