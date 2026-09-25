// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBrowserIdleAndAbsoluteDeadlines(t *testing.T) {
	s, _ := newStockServer(t)
	user := addPasswordUser(t, s, "idle-user", "fixture-password")
	token, _, err := s.mintApplicationSession(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	key := s.sessionHash(token)
	now := time.Now().Unix()
	set := func(created, last, expires int64) {
		t.Helper()
		if err := s.changeForest(func() error {
			v := s.forest.ApplicationSessions[key]
			v.CreatedAt = created
			v.LastActiveAt = last
			v.ExpiresAt = expires
			s.forest.ApplicationSessions[key] = v
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	set(now-7200, now-3601, now+86400)
	if _, ok := s.applicationSession(token); ok {
		t.Fatal("idle session remained valid")
	}
	set(now-86401, now, now+86400)
	if _, ok := s.applicationSession(token); ok {
		t.Fatal("activity extended the absolute lifetime")
	}
	set(now-7200, now-300, now+1000)
	// Session inspection must not renew idle time; only explicit activity does.
	read := s.ApplicationCall(ApplicationRequest{Method:"GET", Target:"/session", Headers:map[string]string{"Authorization":"Bearer "+token}})
	if read.Status != 200 { t.Fatal(string(read.Body)) }
	unchanged, _ := s.applicationSession(token)
	if unchanged.LastActiveAt != now-300 { t.Fatal("session inspection renewed idle deadline") }
	req := httptest.NewRequest("POST", "/session/activity", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	s.handleApplicationActivity(out, req)
	if out.Code != 200 {
		t.Fatal(out.Body.String())
	}
	session, ok := s.applicationSession(token)
	if !ok || session.LastActiveAt < now {
		t.Fatal("interaction did not renew idle deadline")
	}
	if applicationSessionDeadline(session) != now+1000 {
		t.Fatal("idle renewal extended the absolute expiry")
	}
	// Authentication for a background read does not record user activity.
	set(now-7200, now-300, now+86400)
	session, _ = s.applicationSession(token)
	if session.LastActiveAt != now-300 {
		t.Fatal("background validation kept an idle session alive")
	}
}

func TestPhonePromptPreservesFailureBudget(t *testing.T) {
	s, _ := newStockServer(t)
	u := addMFAUser(t, s)
	bad := applicationCall(t, s, "POST", "/session", map[string]string{"username": u.Username, "password": "securepass123", "phone_last4": "0000"})
	if bad.Status != 401 {
		t.Fatal("incorrect digits accepted")
	}
	prompt := applicationCall(t, s, "POST", "/session", map[string]string{"username": u.Username, "password": "securepass123"})
	if prompt.Status != 200 || !strings.Contains(string(prompt.Body), "phone_required") {
		t.Fatal("phone prompt unavailable")
	}
	if s.findUserByName(u.Username).FailedLogins != 1 {
		t.Fatal("phone prompt reset guess budget")
	}
}
