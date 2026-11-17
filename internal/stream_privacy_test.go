// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// Observed red 2026-09-21: administrator stream announced another owner's
// private node path, and "revoked stream remained open" after session deletion.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func TestStreamAdministratorCannotReadAnotherOwnersPrivateActivity(t *testing.T) {
	s, admin, base := streamingServer(t)
	s.forest.Users = append(s.forest.Users, core.User{ID: "private-owner", Username: "private-owner", Permissions: []core.Permission{core.WritePermission}})
	path := workTestCommand(t, s, "private-owner", workCommand{Command: "create", Path: s.forest.Name, Title: "private", Kind: "idea", ClientID: "private"}, 200)["path"].(string)
	reader := openStream(t, base, admin, "")
	defer reader.close()
	waitForSubscriber(t, s)
	workTestCommand(t, s, "private-owner", workCommand{Command: "log", Path: path, Content: "other account content", ClientID: "private-log"}, 200)
	reader.silentFor(t, 50*time.Millisecond)
}

func TestStreamRevokedSessionStopsBeforeDelivering(t *testing.T) {
	s, userID, _ := streamingServer(t)
	token, _, err := s.mintApplicationSession(userID)
	if err != nil {
		t.Fatal(err)
	}
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+r.Header.Get("X-Test-User"))
		s.authMiddleware(s.handleStream)(w, r)
	}))
	defer listener.Close()
	reader := openStream(t, listener.URL, token, "")
	defer reader.close()
	waitForSubscriber(t, s)
	if err = s.changeForest(func() error { delete(s.forest.ApplicationSessions, s.sessionHash(token)); return nil }); err != nil {
		t.Fatal(err)
	}
	s.publish(mutation(mutationMetadataSet, s.forest.Name))
	select {
	case <-reader.done:
	case <-time.After(time.Second):
		t.Fatal("revoked stream remained open")
	}
}

func TestStreamConversationEventsReachMembersOnly(t *testing.T) {
	s, _, base := streamingServer(t)
	tokens := map[string]string{}
	for _, id := range []string{"alice", "bob", "outsider"} {
		s.forest.Users = append(s.forest.Users, core.User{ID: id, Username: id, Permissions: []core.Permission{core.ReadPermission}})
		token, _, err := s.mintApplicationSession(id)
		if err != nil {
			t.Fatal(err)
		}
		tokens[id] = token
	}
	bobStream, outsiderStream := openStream(t, base, "bob", ""), openStream(t, base, "outsider", "")
	defer bobStream.close()
	defer outsiderStream.close()
	if !readsComment(t, bobStream, "connected", time.Second) || !readsComment(t, outsiderStream, "connected", time.Second) {
		t.Fatal("streams did not connect")
	}
	cid := conversationCall(t, s, tokens["alice"], "POST", "/conversations", map[string]interface{}{"kind": "group", "title": "Room", "usernames": []string{"bob"}, "client_id": "c1"}, 200)["id"].(string)
	conversationCall(t, s, tokens["bob"], "POST", "/conversations/"+cid+"/membership", map[string]string{"action": "accept"}, 200)
	mid := conversationCall(t, s, tokens["alice"], "POST", "/conversations/"+cid+"/messages", map[string]string{"content": "secret body text", "client_id": "m1"}, 200)["id"].(string)
	deadline, seen := time.After(time.Second), []mutationEvent{}
	nextLine := func() string {
		select {
		case line := <-bobStream.lines:
			return line
		case <-deadline:
			t.Fatal("timed out waiting for conversation events")
			return ""
		}
	}
	for len(seen) < 3 {
		line := nextLine()
		if strings.Contains(line, "secret body text") {
			t.Fatalf("stream leaked message body: %s", line)
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var ev mutationEvent
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err != nil {
			t.Fatal(err)
		}
		seen = append(seen, ev)
	}
	if seen[0].Type != mutationConversationCreated || seen[0].ConversationID != cid || seen[0].NodePath != "" || seen[1].Type != mutationConversationMembership || seen[1].ConversationID != cid || seen[2].Type != mutationMessageSent || seen[2].ConversationID != cid || seen[2].MessageID != mid {
		t.Fatalf("unexpected conversation events: %+v", seen)
	}
	outsiderStream.silentFor(t, 50*time.Millisecond)
}
