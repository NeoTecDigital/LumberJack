// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// Observed red 2026-09-21: mismatched create retry and invitation over capacity
// both returned 200 instead of 409; include-history was a sequence sentinel.

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func conversationFixture(t *testing.T) (*Server, map[string]string) {
	t.Helper()
	s := setupTestForest(t)
	tokens := map[string]string{}
	for _, id := range []string{"admin", "alice", "bob", "eve"} {
		if id != "admin" {
			s.forest.Users = append(s.forest.Users, core.User{ID: id, Username: id, Permissions: []core.Permission{core.ReadPermission}})
		}
		token, _, err := s.mintApplicationSession(id)
		if err != nil {
			t.Fatal(err)
		}
		tokens[id] = token
	}
	return s, tokens
}

func TestConversationCreateRetriesVerifyPayloadAndMembership(t *testing.T) {
	s, tokens := conversationFixture(t)
	create := map[string]interface{}{"kind": "group", "title": "Private planning", "usernames": []string{"bob"}, "client_id": "create"}
	answer := conversationCall(t, s, tokens["alice"], "POST", "/conversations", create, 200)
	path := "/conversations/" + answer["id"].(string)
	replay := conversationCall(t, s, tokens["alice"], "POST", "/conversations", create, 200)
	if replay["id"] != answer["id"] {
		t.Fatal("identical retry duplicated conversation")
	}
	different := map[string]interface{}{"kind": "group", "title": "Different payload", "usernames": []string{"bob"}, "client_id": "create"}
	conversationCall(t, s, tokens["alice"], "POST", "/conversations", different, 409)
	conversationCall(t, s, tokens["bob"], "POST", path+"/membership", map[string]string{"action": "accept"}, 200)
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]string{"action": "transfer", "username": "bob"}, 200)
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]string{"action": "leave"}, 200)
	conversationCall(t, s, tokens["alice"], "POST", "/conversations", create, 404)
	conversationCall(t, s, tokens["alice"], "GET", path+"/messages", nil, 404)
}

func TestConversationHistoryInvitationUsesExplicitFlag(t *testing.T) {
	s, tokens := conversationFixture(t)
	answer := conversationCall(t, s, tokens["alice"], "POST", "/conversations", map[string]interface{}{"kind": "group", "title": "Planning", "client_id": "history"}, 200)
	id := answer["id"].(string)
	path := "/conversations/" + id
	conversationCall(t, s, tokens["alice"], "POST", path+"/membership", map[string]interface{}{"action": "invite", "username": "bob", "include_history": true}, 200)
	member := s.forest.Conversations[id].Members["bob"]
	raw, _ := json.Marshal(member)
	var fields map[string]interface{}
	_ = json.Unmarshal(raw, &fields)
	if fields["include_history"] != true || member.From == ^uint64(0) {
		t.Fatal("history sharing must be an explicit invitation flag, not a sequence sentinel")
	}
}

func TestConversationInvitesRespectParticipantLimit(t *testing.T) {
	s, tokens := conversationFixture(t)
	answer := conversationCall(t, s, tokens["alice"], "POST", "/conversations", map[string]interface{}{"kind": "group", "title": "At capacity", "client_id": "capacity"}, 200)
	id := answer["id"].(string)
	c := s.forest.Conversations[id]
	for i := 1; i < 100; i++ {
		user := fmt.Sprintf("member-%d", i)
		s.forest.Users = append(s.forest.Users, core.User{ID: user, Username: user})
		c.Members[user] = core.ConversationMember{Invited: true}
	}
	before, _ := json.Marshal(c)
	conversationCall(t, s, tokens["alice"], "POST", "/conversations/"+id+"/membership", map[string]string{"action": "invite", "username": "bob"}, 409)
	after, _ := json.Marshal(c)
	if string(before) != string(after) {
		t.Fatal("rejected invitation changed conversation")
	}
}
