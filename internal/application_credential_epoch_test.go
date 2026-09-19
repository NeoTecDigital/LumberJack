// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// ENROLLING AN ACCOUNT MUST EVICT WHAT WAS ISSUED BEFORE IT.
//
// The front door was already right: a password alone cannot get a fresh credential for an enrolled
// account — /login answers a challenge and /session answers a challenge. The hole was BEHIND it.
// Everything minted while the account was password-only kept working afterwards: the browser cookie,
// the JWT session, and — worst — the seven-day refresh token, which minted brand new sessions with no
// code at all. Turning the second factor on is the act of saying "a password is no longer enough for
// this account", and it was not retroactive, so an attacker who had already spent the password
// simply never came back through the door that had been shut.
//
// These are the four credentials that outlive the policy change, plus the two cases a fix must not
// break: a user who completes the second factor normally keeps a working session AND a working
// refresh, and an enrolment that changes nothing evicts nothing.

// addEnrollableUser plants an ordinary password account with a number already on file and the second
// factor OFF — the exact state an administrator turns one ON from, and the state every standing
// credential in these cases was minted in.
func addEnrollableUser(t *testing.T, server *Server, username string) core.User {
	t.Helper()
	user := core.User{ID: core.GenerateUserID(), Username: username, Phone: "15558675309"}
	if err := user.SetPassword("securepass123"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := server.changeForest(func() error {
		return server.forest.AssignUser(user, core.ReadPermission)
	}); err != nil {
		t.Fatalf("AssignUser: %v", err)
	}
	return user
}

// enrolAs posts an enrolment through the administrative route and insists it landed. The number it
// sends below is the SAME number the account already carries once digitsOnly has read it, so the one
// thing that changes is the flag — which is what makes these cases about enabling a second factor
// rather than about re-pointing a phone.
func enrolAs(t *testing.T, server *Server, adminToken string, body map[string]interface{}) {
	t.Helper()
	request := jsonRequest(t, "POST", "/users/mfa", body)
	request.Header.Set("Authorization", adminToken)
	if recorder := serve(t, server, request); recorder.Code != http.StatusOK {
		t.Fatalf("POST /users/mfa: got %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
}

// profileWith asks GET /users/profile carrying one bearer. It is the route the defect was proven on,
// and it is behind authMiddleware, so a refusal here is the guard's refusal and not a handler's.
func profileWith(t *testing.T, server *Server, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest("GET", "/users/profile", nil)
	request.Header.Set("Authorization", "Bearer "+bearer)
	return serve(t, server, request)
}

// refreshWith posts a refresh token to /refresh, the route that turns a week-old bearer into a
// working session with no credential presented at all.
func refreshWith(t *testing.T, server *Server, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()
	return serve(t, server, jsonRequest(t, "POST", "/refresh", map[string]interface{}{
		"refresh_token": refreshToken,
	}))
}

// passwordOnlyPair logs an account in with nothing but its password and hands back the pair, having
// first insisted the account really is password-only at that moment.
func passwordOnlyPair(t *testing.T, server *Server, username string) (string, string) {
	t.Helper()
	answer := login(t, server, map[string]interface{}{"username": username, "password": "securepass123"})
	if answer.status != http.StatusOK {
		t.Fatalf("a password-only login answered %d: %v", answer.status, answer.json)
	}
	session, _ := answer.json["session_token"].(string)
	refresh, _ := answer.json["refresh_token"].(string)
	if session == "" || refresh == "" {
		t.Fatalf("the login handed back an incomplete pair: %v", answer.json)
	}
	return session, refresh
}

// TestEnrolmentEvictsAStandingJWTSession is the first of the four: a session token minted while the
// account was password-only answers 200 on a guarded route, and must stop the moment the account
// carries a second factor.
//
// OBSERVED RED (against the engine at cb46866, before any of this existed,
// `go test ./internal -run TestEnrolmentEvictsAStandingJWTSession -count=1`):
//
//	--- FAIL: TestEnrolmentEvictsAStandingJWTSession (0.24s)
//	    application_credential_epoch_test.go:117: a session minted before enrolment still answered 200 on GET /users/profile
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.245s
func TestEnrolmentEvictsAStandingJWTSession(t *testing.T) {
	server, _ := newStockServer(t)
	adminToken := "Bearer " + sessionFor(t, server, adminID(t, server), "admin")
	user := addEnrollableUser(t, server, "standing-user")

	session, _ := passwordOnlyPair(t, server, user.Username)
	if got := profileWith(t, server, session); got.Code != http.StatusOK {
		t.Fatalf("the session did not work BEFORE enrolment (%d): the case proves nothing", got.Code)
	}

	enrolAs(t, server, adminToken, map[string]interface{}{
		"user_id": user.ID, "phone": "+1 (555) 867-5309", "mfa_enabled": true,
	})

	if got := profileWith(t, server, session); got.Code != http.StatusUnauthorized {
		t.Fatalf("a session minted before enrolment still answered %d on GET /users/profile", got.Code)
	}
}

// TestEnrolmentEvictsAStandingRefreshToken is the worst of the four, because the refresh token lives
// SEVEN DAYS and hands out a brand new working session for nothing but its own signature. An account
// enrolled on Monday was still mintable from a Sunday token on Saturday.
//
// OBSERVED RED (same build, `go test ./internal -run TestEnrolmentEvictsAStandingRefreshToken -count=1`):
//
//	--- FAIL: TestEnrolmentEvictsAStandingRefreshToken (0.24s)
//	    application_credential_epoch_test.go:147: a refresh token minted before enrolment answered 200 and minted a session with no code
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.243s
func TestEnrolmentEvictsAStandingRefreshToken(t *testing.T) {
	server, _ := newStockServer(t)
	adminToken := "Bearer " + sessionFor(t, server, adminID(t, server), "admin")
	user := addEnrollableUser(t, server, "refreshing-user")

	_, refresh := passwordOnlyPair(t, server, user.Username)
	if got := refreshWith(t, server, refresh); got.Code != http.StatusOK {
		t.Fatalf("the refresh token did not work BEFORE enrolment (%d): the case proves nothing", got.Code)
	}

	enrolAs(t, server, adminToken, map[string]interface{}{
		"user_id": user.ID, "phone": "+1 (555) 867-5309", "mfa_enabled": true,
	})

	refused := refreshWith(t, server, refresh)
	if refused.Code != http.StatusUnauthorized {
		t.Fatalf("a refresh token minted before enrolment answered %d and minted a session with no code", refused.Code)
	}
	// And nothing usable came back with it, which is the fact the status is standing in for.
	var minted map[string]interface{}
	_ = json.Unmarshal(refused.Body.Bytes(), &minted)
	if session, _ := minted["session_token"].(string); session != "" {
		if got := profileWith(t, server, session); got.Code == http.StatusOK {
			t.Fatalf("the session that refresh minted answered %d on GET /users/profile", got.Code)
		}
	}
}

// TestEnrolmentEvictsAStandingBrowserSession is the ms_ half. It is the credential a browser
// actually holds — the relay parks it in a cookie — so it is the one an attacker who spent a
// password is most likely to be sitting on when the administrator reacts.
//
// OBSERVED RED (same build, `go test ./internal -run TestEnrolmentEvictsAStandingBrowserSession -count=1`):
//
//	--- FAIL: TestEnrolmentEvictsAStandingBrowserSession (0.24s)
//	    application_credential_epoch_test.go:193: a browser session minted before enrolment still answered 200 on GET /users/profile
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.241s
func TestEnrolmentEvictsAStandingBrowserSession(t *testing.T) {
	server, _ := newStockServer(t)
	adminToken := "Bearer " + sessionFor(t, server, adminID(t, server), "admin")
	user := addEnrollableUser(t, server, "browsing-user")

	opened := applicationCall(t, server, "POST", "/session", map[string]string{
		"username": user.Username, "password": "securepass123",
	})
	if opened.Status != http.StatusOK {
		t.Fatalf("POST /session answered %d: %s", opened.Status, string(opened.Body))
	}
	cookie, _ := decodeApplication(t, opened)["token"].(string)
	if cookie == "" {
		t.Fatalf("POST /session handed back no token: %s", string(opened.Body))
	}
	if got := profileWith(t, server, cookie); got.Code != http.StatusOK {
		t.Fatalf("the browser session did not work BEFORE enrolment (%d): the case proves nothing", got.Code)
	}

	enrolAs(t, server, adminToken, map[string]interface{}{
		"user_id": user.ID, "phone": "+1 (555) 867-5309", "mfa_enabled": true,
	})

	if got := profileWith(t, server, cookie); got.Code != http.StatusUnauthorized {
		t.Fatalf("a browser session minted before enrolment still answered %d on GET /users/profile", got.Code)
	}
}

// TestRepointingTheNumberEvictsALiveChallenge is the fourth, and it is about the OTHER thing this
// route does. Re-pointing an account's phone is what an administrator does when the old handset is
// gone; a code already in flight to the old handset must not still complete the login, or the act of
// taking the number away leaves a five-minute window in which it still works.
//
// OBSERVED RED (same build, `go test ./internal -run TestRepointingTheNumberEvictsALiveChallenge -count=1`):
//
//	--- FAIL: TestRepointingTheNumberEvictsALiveChallenge (0.24s)
//	    application_credential_epoch_test.go:225: a code sent to the OLD number completed the login after the number was re-pointed
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.242s
func TestRepointingTheNumberEvictsALiveChallenge(t *testing.T) {
	server, _ := newStockServer(t)
	adminToken := "Bearer " + sessionFor(t, server, adminID(t, server), "admin")
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)
	code := outboundFor(t, server, challengeID).Payload

	enrolAs(t, server, adminToken, map[string]interface{}{
		"user_id": user.ID, "phone": "555-111-2222", "mfa_enabled": true,
	})

	if _, err := server.verifyMFAChallenge(token, code); err == nil {
		t.Fatal("a code sent to the OLD number completed the login after the number was re-pointed")
	}
}

// TestCompletingTheSecondFactorKeepsAWorkingSessionAndRefresh is the case a fix breaks first, and
// the reason a blunt "evict everything for this account" is not enough on its own: the credential
// the SECOND FACTOR ITSELF mints arrives after the enrolment, so it must be current, and so must the
// session its refresh token goes on to mint. consumeMFAChallenge hands its caller a deliberately
// minimal user — an id and a username — and a minimal user is exactly where a freshly-minted
// credential loses the stamp that keeps it alive.
//
// OBSERVED RED (with the fix in, consumeMFAChallenge's minimal user left without the account's
// epoch — the trap this case exists for —
// `go test ./internal -run TestCompletingTheSecondFactorKeepsAWorkingSessionAndRefresh -count=1`):
//
//	--- FAIL: TestCompletingTheSecondFactorKeepsAWorkingSessionAndRefresh (0.35s)
//	    application_credential_epoch_test.go:268: the session a completed second factor minted answered 401 on GET /users/profile
//	    application_credential_epoch_test.go:272: the refresh token a completed second factor minted answered 401
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.351s
func TestCompletingTheSecondFactorKeepsAWorkingSessionAndRefresh(t *testing.T) {
	server, _ := newStockServer(t)
	adminToken := "Bearer " + sessionFor(t, server, adminID(t, server), "admin")
	user := addEnrollableUser(t, server, "compliant-user")

	enrolAs(t, server, adminToken, map[string]interface{}{
		"user_id": user.ID, "phone": "+1 (555) 867-5309", "mfa_enabled": true,
	})

	answer := login(t, server, map[string]interface{}{
		"username": user.Username, "password": "securepass123", "phone_last4": "5309",
	})
	challenge, _ := answer.json["challenge"].(string)
	if answer.status != http.StatusOK || challenge == "" {
		t.Fatalf("the enrolled login answered %d with no challenge: %v", answer.status, answer.json)
	}
	code := outboundFor(t, server, challengeIDOf(t, server, challenge)).Payload

	pair, err := server.verifyMFAChallenge(challenge, code)
	if err != nil || pair == nil {
		t.Fatalf("the correct code did not complete the login: %v", err)
	}
	if got := profileWith(t, server, pair.SessionToken); got.Code != http.StatusOK {
		t.Errorf("the session a completed second factor minted answered %d on GET /users/profile", got.Code)
	}
	renewed := refreshWith(t, server, pair.RefreshToken)
	if renewed.Code != http.StatusOK {
		t.Fatalf("the refresh token a completed second factor minted answered %d", renewed.Code)
	}
	var minted map[string]interface{}
	if err := json.Unmarshal(renewed.Body.Bytes(), &minted); err != nil {
		t.Fatalf("the refresh answer was not JSON: %q", renewed.Body.String())
	}
	session, _ := minted["session_token"].(string)
	if session == "" {
		t.Fatalf("the refresh answered 200 with no session token: %v", minted)
	}
	if got := profileWith(t, server, session); got.Code != http.StatusOK {
		t.Errorf("the session that refresh went on to mint answered %d", got.Code)
	}
}

// TestAnEnrolmentThatChangesNothingEvictsNothing is the other half of not breaking the working case.
// An administrative console that re-posts the account it is already looking at must not sign
// everybody out for nothing, so the eviction has to hang off a REAL change to the second factor and
// not off the route having been called.
//
// OBSERVED RED (with the fix in, the epoch bumped unconditionally rather than on a change,
// `go test ./internal -run TestAnEnrolmentThatChangesNothingEvictsNothing -count=1`):
//
//	--- FAIL: TestAnEnrolmentThatChangesNothingEvictsNothing (0.24s)
//	    application_credential_epoch_test.go:313: re-posting the enrolment an account already had answered 401 on GET /users/profile
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.245s
func TestAnEnrolmentThatChangesNothingEvictsNothing(t *testing.T) {
	server, _ := newStockServer(t)
	adminToken := "Bearer " + sessionFor(t, server, adminID(t, server), "admin")
	user := addEnrollableUser(t, server, "unchanged-user")

	session, refresh := passwordOnlyPair(t, server, user.Username)

	// The account already carries this number and already carries no second factor, so nothing here
	// is a change — digitsOnly reads the same digits back out of the formatted form.
	enrolAs(t, server, adminToken, map[string]interface{}{
		"user_id": user.ID, "phone": "+1 (555) 867-5309", "mfa_enabled": false,
	})

	if got := profileWith(t, server, session); got.Code != http.StatusOK {
		t.Errorf("re-posting the enrolment an account already had answered %d on GET /users/profile", got.Code)
	}
	if got := refreshWith(t, server, refresh); got.Code != http.StatusOK {
		t.Errorf("re-posting the enrolment an account already had answered %d on POST /refresh", got.Code)
	}
}
