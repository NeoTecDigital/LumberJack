// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

// Observed red 2026-09-21: administrator stream announced another owner's
// private node path, and "revoked stream remained open" after session deletion.

import (
	"net/http"
	"net/http/httptest"
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
