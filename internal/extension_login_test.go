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

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
)

// The password exchange through the SecondFactor seam, the fail-closed default (owner decision
// Q1(a)), the session registry an extension finishes a login with, and the outbox listener
// (docs/extension-api.md §4.4, §4.6). The factor and listener are test doubles; no product code.

func addLoginUser(t *testing.T, server *Server, username string, enrol func(*core.User)) core.User {
	t.Helper()
	user := core.User{ID: core.GenerateUserID(), Username: username}
	if err := user.SetPassword("a-long-enough-password"); err != nil {
		t.Fatal(err)
	}
	if enrol != nil {
		enrol(&user)
	}
	if err := server.changeForest(func() error { return server.forest.AssignUser(user, core.ReadPermission) }); err != nil {
		t.Fatal(err)
	}
	return user
}

func passwordBody(user core.User) map[string]interface{} {
	return map[string]interface{}{"username": user.Username, "password": "a-long-enough-password"}
}

func failedLoginsOf(server *Server, username string) int {
	return server.findUserByName(username).FailedLogins
}

func TestLoginWithoutSecondFactorIssues(t *testing.T) {
	server, _ := newStockServer(t)
	user := addLoginUser(t, server, "plain", nil)
	if result := login(t, server, passwordBody(user)); result.status != 200 || result.json["session_token"] == nil || result.json["refresh_token"] == nil {
		t.Fatalf("/login answered %d %v", result.status, result.json)
	}
	browser := applicationCall(t, server, "POST", "/session", passwordBody(user))
	if browser.Status != 200 || !strings.HasPrefix(decodeApplication(t, browser)["token"].(string), "ms_") {
		t.Fatalf("POST /session answered %d %s", browser.Status, browser.Body)
	}
}

// Both triggers, both transports: an enrolled account is refused 401 "second factor required" when
// no SecondFactor is registered, and the refusal is not counted against the account.
func TestEnrolledAccountFailsClosedWithoutSecondFactor(t *testing.T) {
	server, _ := newStockServer(t)
	flagged := addLoginUser(t, server, "flagged", func(u *core.User) { u.MFAEnabled = true })
	listed := addLoginUser(t, server, "listed", nil)
	if err := server.changeForest(func() error {
		server.forest.AccountSecurity = map[string]core.AccountSecurity{listed.ID: {}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, user := range []core.User{flagged, listed} {
		if result := login(t, server, passwordBody(user)); result.status != http.StatusUnauthorized || result.json["session_token"] != nil {
			t.Errorf("%s: /login answered %d %v", user.Username, result.status, result.json)
		}
		browser := applicationCall(t, server, "POST", "/session", passwordBody(user))
		if browser.Status != http.StatusUnauthorized || !strings.Contains(string(browser.Body), "second factor required") {
			t.Errorf("%s: POST /session answered %d %s", user.Username, browser.Status, browser.Body)
		}
		if failed := failedLoginsOf(server, user.Username); failed != 0 {
			t.Errorf("%s: the fail-closed refusal was counted %d times", user.Username, failed)
		}
	}
}

// testFactor requires a second step of one account, holds the code it would have sent, and
// finishes the login through Sessions.Issue.
type testFactor struct {
	host   extension.Host
	userID string
	codes  map[string]string // challenge -> code
}

func (f *testFactor) Close(context.Context) error { return nil }

func (f *testFactor) Required(_ extension.ReadTx, user core.User) bool { return user.ID == f.userID }

func (f *testFactor) AfterPassword(_ context.Context, user core.User, login extension.Login) (*extension.Challenge, error) {
	if string(login.Extras["hint"]) != `"present"` {
		return nil, extension.ErrInvalidCredentials
	}
	f.codes["challenge-"+user.ID] = "424242"
	return &extension.Challenge{Body: map[string]string{"challenge": "challenge-" + user.ID}}, nil
}

func (f *testFactor) complete(challenge, code string) (extension.TokenPair, error) {
	if f.codes[challenge] != code {
		return extension.TokenPair{}, errors.New("wrong code")
	}
	var pair extension.TokenPair
	_, err := f.host.Change(context.Background(), extension.WriteOp{Key: challenge}, func(tx extension.Tx) error {
		var err error
		pair, err = f.host.Sessions().Issue(tx, f.userID, extension.SessionOptions{Transport: "bearer"})
		return err
	})
	return pair, err
}

func withFactor(t *testing.T, server *Server, factor *testFactor) {
	t.Helper()
	ext := testExtension{spec: extension.Spec{Name: "test-factor"}, attach: func(host extension.Host) (extension.Instance, error) {
		factor.host = host
		return factor, nil
	}}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
}

func TestSecondFactorChallengeThenIssue(t *testing.T) {
	server, _ := newStockServer(t)
	enrolled := addLoginUser(t, server, "enrolled", func(u *core.User) { u.MFAEnabled = true })
	other := addLoginUser(t, server, "other", nil)
	factor := &testFactor{userID: enrolled.ID, codes: map[string]string{}}
	withFactor(t, server, factor)
	if result := login(t, server, passwordBody(other)); result.status != 200 || result.json["session_token"] == nil {
		t.Fatalf("an account the factor does not require answered %d %v", result.status, result.json)
	}
	if result := login(t, server, passwordBody(enrolled)); result.status != 401 {
		t.Fatalf("the factor's refusal answered %d", result.status)
	}
	body := passwordBody(enrolled)
	body["hint"] = "present"
	result := login(t, server, body)
	if result.status != 200 || result.json["challenge"] != "challenge-"+enrolled.ID || result.json["session_token"] != nil {
		t.Fatalf("the challenge answered %d %v", result.status, result.json)
	}
	pair, err := factor.complete("challenge-"+enrolled.ID, "424242")
	if err != nil || pair.SessionToken == "" || pair.RefreshToken == "" {
		t.Fatalf("Issue answered %+v, %v", pair, err)
	}
	request := httptest.NewRequest("GET", "/forest", nil)
	request.Header.Set("Authorization", "Bearer "+pair.SessionToken)
	if code := serve(t, server, request).Code; code != 200 {
		t.Fatalf("the issued session answered %d", code)
	}
	second := &testFactor{userID: enrolled.ID, codes: map[string]string{}}
	two := []extension.Extension{
		testExtension{spec: extension.Spec{Name: "one"}, attach: func(extension.Host) (extension.Instance, error) { return factor, nil }},
		testExtension{spec: extension.Spec{Name: "two"}, attach: func(extension.Host) (extension.Instance, error) { return second, nil }},
	}
	bare, _ := newStockServer(t)
	if err := bare.AttachExtensions(two); !errors.Is(err, ErrExtensionSet) {
		t.Fatalf("two second factors were accepted: %v", err)
	}
}

// RetireCredentials moves the account to a new epoch inside the change, which ends every session
// minted under the old one.
func TestRetireCredentialsEndsEarlierSessions(t *testing.T) {
	server, _ := newStockServer(t)
	user := addLoginUser(t, server, "retiring", nil)
	factor := &testFactor{userID: "nobody", codes: map[string]string{}}
	withFactor(t, server, factor)
	before := login(t, server, passwordBody(user))
	if before.status != 200 {
		t.Fatalf("login answered %d", before.status)
	}
	if _, err := factor.host.Change(context.Background(), extension.WriteOp{Key: "retire"}, func(tx extension.Tx) error {
		factor.host.Sessions().RetireCredentials(tx, user.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/forest", nil)
	request.Header.Set("Authorization", "Bearer "+before.json["session_token"].(string))
	if code := serve(t, server, request).Code; code != http.StatusUnauthorized {
		t.Fatalf("a session minted before the retirement answered %d", code)
	}
}

type testListener struct {
	settled []extension.OutboundOutcome
	items   []string
}

func (l *testListener) Close(context.Context) error { return nil }

func (l *testListener) OutboundSettledLocked(_ extension.Tx, item core.OutboundMessage, outcome extension.OutboundOutcome) bool {
	l.settled = append(l.settled, outcome)
	l.items = append(l.items, item.ID)
	return item.ChallengeID != ""
}

func TestOutboundAckNotifiesListener(t *testing.T) {
	server, _ := newStockServer(t)
	listener := &testListener{}
	var host extension.Host
	ext := testExtension{spec: extension.Spec{Name: "listener"}, attach: func(h extension.Host) (extension.Instance, error) {
		host = h
		return listener, nil
	}}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Change(context.Background(), extension.WriteOp{Key: "enqueue"}, func(tx extension.Tx) error {
		for _, id := range []string{"sent", "expired", "failed"} {
			if err := tx.EnqueueOutbound(core.OutboundMessage{ID: id, Channel: "sms", ChallengeID: "c-" + id}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Change(context.Background(), extension.WriteOp{Key: "again"}, func(tx extension.Tx) error {
		return tx.EnqueueOutbound(core.OutboundMessage{ID: "sent"})
	}); err == nil {
		t.Fatal("a duplicate outbound id was accepted")
	}
	var acked, failed map[string]interface{}
	_ = json.Unmarshal(hubOut(t, server, map[string]interface{}{"operation": "outbound_ack", "id": "sent", "attempts": 1}), &acked)
	hubOut(t, server, map[string]interface{}{"operation": "outbound_ack", "id": "expired", "outcome": "expired"})
	_ = json.Unmarshal(hubOut(t, server, map[string]interface{}{"operation": "outbound_failed", "id": "failed", "error_class": "provider", "attempts": 3}), &failed)
	if acked["acked"] != true || failed["recorded"] != true || failed["cleared"] != true {
		t.Fatalf("hub answers %v %v", acked, failed)
	}
	if strings.Join(listener.items, ",") != "sent,failed" || listener.settled[0].State != extension.OutboundSent ||
		listener.settled[1].State != extension.OutboundFailed || listener.settled[1].ErrorClass != "provider" || listener.settled[1].Attempts != 3 {
		t.Fatalf("the listener heard %v %+v", listener.items, listener.settled)
	}
}
