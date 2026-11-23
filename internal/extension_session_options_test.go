// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/extension"
)

type sessionTestInstance struct{}

func (sessionTestInstance) Close(context.Context) error { return nil }

func attachSessionTestHost(t *testing.T, server *Server) extension.Host {
	t.Helper()
	var host extension.Host
	ext := testExtension{
		spec: extension.Spec{Name: "session-options-test", Scope: extension.HubStore},
		attach: func(attached extension.Host) (extension.Instance, error) {
			host = attached
			return sessionTestInstance{}, nil
		},
	}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
	return host
}

func issueWithHost(host extension.Host, key, userID string, opts extension.SessionOptions) (extension.TokenPair, error) {
	var pair extension.TokenPair
	_, err := host.Change(context.Background(), extension.WriteOp{Key: key}, func(tx extension.Tx) error {
		var issueErr error
		pair, issueErr = host.Sessions().Issue(tx, userID, opts)
		return issueErr
	})
	return pair, err
}

func sessionStatus(t *testing.T, server *Server, method, target, token string) (int, map[string]interface{}) {
	t.Helper()
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	reply := server.ApplicationCall(ApplicationRequest{Method: method, Target: target, Headers: headers})
	if reply.Status != http.StatusOK {
		return reply.Status, nil
	}
	return reply.Status, decodeApplication(t, reply)
}

func TestSessionOptionsDefaultIssueUnchanged(t *testing.T) {
	server, _ := newStockServer(t)
	user := addLoginUser(t, server, "default-options", nil)
	host := attachSessionTestHost(t, server)

	bearer, err := issueWithHost(host, "bearer-default", user.ID, extension.SessionOptions{Transport: "bearer"})
	if err != nil || bearer.SessionToken == "" || bearer.RefreshToken == "" || bearer.ExpiresAt != 0 {
		t.Fatalf("default bearer Issue: %+v, %v", bearer, err)
	}
	req := httptest.NewRequest("GET", "/forest", nil)
	req.Header.Set("Authorization", "Bearer "+bearer.SessionToken)
	if code := serve(t, server, req).Code; code != http.StatusOK {
		t.Fatalf("bearer token answered %d", code)
	}

	browser, err := issueWithHost(host, "browser-default", user.ID, extension.SessionOptions{Transport: "browser"})
	if err != nil || !strings.HasPrefix(browser.SessionToken, "ms_") || browser.RefreshToken != "" {
		t.Fatalf("default browser Issue: %+v, %v", browser, err)
	}
	held, ok := server.applicationSession(browser.SessionToken)
	if !ok || held.Delegated || held.SourceSession != "" || held.ExpiresAt != held.CreatedAt+applicationSessionTTL {
		t.Fatalf("unexpected default browser session record: ok=%v %+v", ok, held)
	}
	if browser.ExpiresAt != held.CreatedAt+applicationSessionIdleTTL {
		t.Fatalf("default browser ExpiresAt = %d, want %d", browser.ExpiresAt, held.CreatedAt+applicationSessionIdleTTL)
	}
}

func TestSessionOptionsRefusalsLeaveRegistryUntouched(t *testing.T) {
	server, _ := newStockServer(t)
	user := addLoginUser(t, server, "refusal-user", nil)
	host := attachSessionTestHost(t, server)

	badCases := []extension.SessionOptions{
		{Transport: "bearer", Lifetime: 10 * time.Minute},
		{Transport: "bearer", SourceSession: "auth-session-1"},
		{Transport: "", Lifetime: 10 * time.Minute},
		{Transport: "", SourceSession: "auth-session-1"},
		{Transport: "unknown"},
		{Transport: "browser", Lifetime: -time.Second},
		{Transport: "browser", Lifetime: 500 * time.Millisecond},
		{Transport: "browser", Lifetime: time.Nanosecond},
		{Transport: "browser", Lifetime: 24*time.Hour + time.Second},
		{Transport: "browser", Lifetime: 24*time.Hour + time.Nanosecond},
		{Transport: "browser", SourceSession: "has space"},
		{Transport: "browser", SourceSession: "tab\tkey"},
		{Transport: "browser", SourceSession: "line\nkey"},
		{Transport: "browser", SourceSession: "ctrl\x00key"},
		{Transport: "browser", SourceSession: "del\x7fkey"},
		{Transport: "browser", SourceSession: "utf8\xffkey"},
		{Transport: "browser", SourceSession: strings.Repeat("k", 257)},
	}
	for index, opts := range badCases {
		pair, err := issueWithHost(host, "bad-"+string(rune('a'+index)), user.ID, opts)
		var carried *apiError
		if err == nil || !errors.As(err, &carried) || carried.status != http.StatusBadRequest || pair.SessionToken != "" {
			t.Fatalf("case %d (%+v): got pair=%+v err=%v", index, opts, pair, err)
		}
	}
	server.readForest(func() {
		if len(server.forest.ApplicationSessions) != 0 {
			t.Fatalf("refused options mutated ApplicationSessions: %d entries", len(server.forest.ApplicationSessions))
		}
	})
}

func TestSessionOptionsBoundedBrowserExpiryIdleAndEpoch(t *testing.T) {
	server, _ := newStockServer(t)
	user := addLoginUser(t, server, "bounded-user", nil)
	host := attachSessionTestHost(t, server)

	if oneSec, err := issueWithHost(host, "min-bound", user.ID, extension.SessionOptions{Transport: "browser", Lifetime: time.Second}); err != nil || oneSec.ExpiresAt == 0 {
		t.Fatalf("1s bound failed: %+v, %v", oneSec, err)
	}
	if maxDay, err := issueWithHost(host, "max-bound", user.ID, extension.SessionOptions{Transport: "browser", Lifetime: 24 * time.Hour}); err != nil || maxDay.ExpiresAt == 0 {
		t.Fatalf("24h bound failed: %+v, %v", maxDay, err)
	}

	pair, err := issueWithHost(host, "ten-min", user.ID, extension.SessionOptions{Transport: "browser", Lifetime: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	held, ok := server.applicationSession(pair.SessionToken)
	if !ok || held.ExpiresAt != held.CreatedAt+600 || pair.ExpiresAt != held.CreatedAt+600 {
		t.Fatalf("bounded 600s session mismatch: pair=%+v held=%+v", pair, held)
	}
	code, body := sessionStatus(t, server, "POST", "/session/activity", pair.SessionToken)
	if code != http.StatusOK || int64(body["absolute_expires_at"].(float64)) != held.ExpiresAt {
		t.Fatalf("activity altered absolute bound: %d %v", code, body)
	}

	key := server.sessionHash(pair.SessionToken)
	now := time.Now().Unix()
	_ = server.changeForest(func() error {
		s := server.forest.ApplicationSessions[key]
		s.CreatedAt, s.LastActiveAt, s.ExpiresAt = now-600, now-10, now
		server.forest.ApplicationSessions[key] = s
		return nil
	})
	if status, _ := sessionStatus(t, server, "GET", "/session", pair.SessionToken); status != http.StatusUnauthorized {
		t.Fatalf("expired bounded session answered %d", status)
	}
	checkBoundedIdleAndEpoch(t, server, host, user.ID)
}

func checkBoundedIdleAndEpoch(t *testing.T, server *Server, host extension.Host, userID string) {
	t.Helper()
	twoHour, err := issueWithHost(host, "two-hour", userID, extension.SessionOptions{Transport: "browser", Lifetime: 2 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	key := server.sessionHash(twoHour.SessionToken)
	_ = server.changeForest(func() error {
		s := server.forest.ApplicationSessions[key]
		s.CreatedAt, s.LastActiveAt, s.ExpiresAt = now-4000, now-3601, now+3200
		server.forest.ApplicationSessions[key] = s
		return nil
	})
	if _, ok := server.applicationSession(twoHour.SessionToken); ok {
		t.Fatal("idle limit did not expire a 2h bounded session")
	}

	grouped, err := issueWithHost(host, "epoch-grouped", userID, extension.SessionOptions{
		Transport: "browser", Lifetime: 10 * time.Minute, SourceSession: "epoch-source-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	host.Sessions().RecordLoginFailure(userID)
	if server.findUserByName("bounded-user").FailedLogins != 1 {
		t.Fatal("RecordLoginFailure changed behavior")
	}
	host.Sessions().ClearLoginFailures(userID)
	if server.findUserByName("bounded-user").FailedLogins != 0 {
		t.Fatal("ClearLoginFailures changed behavior")
	}
	_, _ = host.Change(context.Background(), extension.WriteOp{Key: "retire-epoch"}, func(tx extension.Tx) error {
		host.Sessions().RetireCredentials(tx, userID)
		return nil
	})
	if status, _ := sessionStatus(t, server, "GET", "/session", grouped.SessionToken); status != http.StatusUnauthorized {
		t.Fatalf("retired credential epoch left grouped session valid: %d", status)
	}
}

func TestSessionOptionsSourceSessionAdmissionIsolationAndRevocation(t *testing.T) {
	server, _ := newStockServer(t)
	alice := addLoginUser(t, server, "alice", nil)
	bob := addLoginUser(t, server, "bob", nil)
	host := attachSessionTestHost(t, server)

	// First admission with a new external key succeeds on an account with zero sessions.
	lease1, err := issueWithHost(host, "admit-1", alice.ID, extension.SessionOptions{
		Transport: "browser", Lifetime: 10 * time.Minute, SourceSession: "authority-session-alpha",
	})
	if err != nil {
		t.Fatalf("first grouped admission failed: %v", err)
	}
	held1, ok := server.applicationSession(lease1.SessionToken)
	if !ok || !held1.Delegated || held1.SourceSession != "authority-session-alpha" {
		t.Fatalf("unexpected grouped session state: ok=%v %+v", ok, held1)
	}
	if maxKey, err := issueWithHost(host, "admit-max", alice.ID, extension.SessionOptions{
		Transport: "browser", SourceSession: strings.Repeat("s", 256),
	}); err != nil || maxKey.SessionToken == "" {
		t.Fatalf("256-byte SourceSession failed: %+v, %v", maxKey, err)
	}

	// Second user reusing a live SourceSession key is refused with zero mutation for bob.
	if refused, err := issueWithHost(host, "bob-reuse", bob.ID, extension.SessionOptions{
		Transport: "browser", Lifetime: 10 * time.Minute, SourceSession: "authority-session-alpha",
	}); err == nil || refused.SessionToken != "" {
		t.Fatalf("second user reusing live SourceSession succeeded: %+v, %v", refused, err)
	}
	verifyGroupSignOutIsolation(t, server, host, alice.ID, lease1.SessionToken)
}

func verifyGroupSignOutIsolation(t *testing.T, server *Server, host extension.Host, userID, lease1Token string) {
	t.Helper()
	lease2, err := issueWithHost(host, "admit-2", userID, extension.SessionOptions{
		Transport: "browser", Lifetime: 10 * time.Minute, SourceSession: "authority-session-alpha",
	})
	if err != nil {
		t.Fatalf("same-user renewal in group failed: %v", err)
	}
	ordinary, err := issueWithHost(host, "ordinary-1", userID, extension.SessionOptions{Transport: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	otherGroup, err := issueWithHost(host, "admit-beta", userID, extension.SessionOptions{
		Transport: "browser", Lifetime: 10 * time.Minute, SourceSession: "authority-session-beta",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Signing out one grouped lease ends its sibling in the same group, while leaving the
	// user's ordinary ungrouped session and any other group alive.
	rawDelete, _ := json.Marshal(map[string]bool{})
	delReply := server.ApplicationCall(ApplicationRequest{
		Method: "DELETE", Target: "/session",
		Headers: map[string]string{"Authorization": "Bearer " + lease1Token},
		Body:    rawDelete,
	})
	if delReply.Status != http.StatusOK {
		t.Fatalf("DELETE /session answered %d %s", delReply.Status, delReply.Body)
	}
	if status, _ := sessionStatus(t, server, "GET", "/session", lease1Token); status != http.StatusUnauthorized {
		t.Fatalf("signed-out source lease answered %d", status)
	}
	if status, _ := sessionStatus(t, server, "GET", "/session", lease2.SessionToken); status != http.StatusUnauthorized {
		t.Fatalf("sibling lease in same SourceSession group survived sign-out: %d", status)
	}
	if status, _ := sessionStatus(t, server, "GET", "/session", ordinary.SessionToken); status != http.StatusOK {
		t.Fatalf("ordinary session of same user was ended by grouped sign-out: %d", status)
	}
	if status, _ := sessionStatus(t, server, "GET", "/session", otherGroup.SessionToken); status != http.StatusOK {
		t.Fatalf("unrelated SourceSession group of same user was ended: %d", status)
	}
}
