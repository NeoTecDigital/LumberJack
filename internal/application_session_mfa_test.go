package internal

import (
	"encoding/json"
	"strings"
	"testing"
)

// THE BYPASS THESE CLOSE. /session minted an application session for any account whose password
// verified, MFA or not — so the whole second factor was optional for anything speaking the
// application surface, which is every browser client. /login had the gate; /session did not.
//
// /session and /session/mfa are NOT on the HTTP router: ApplicationCall dispatches them by path.
// These cases therefore go through ApplicationCall, so the routing is asserted along with the
// behaviour — a handler that exists but is not reachable fails here exactly as a missing one does.

// applicationCall posts a JSON body through the embedded application surface with no Authorization
// header, which is the position a browser is in before it holds anything.
func applicationCall(t *testing.T, server *Server, method, target string, body interface{}) ApplicationResponse {
	t.Helper()
	var raw []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode %s %s: %v", method, target, err)
		}
		raw = encoded
	}
	return server.ApplicationCall(ApplicationRequest{Method: method, Target: target, Headers: map[string]string{"Content-Type": "application/json"}, Body: raw})
}

// decodeApplication reads a JSON answer, failing the test on a body that is not one.
func decodeApplication(t *testing.T, response ApplicationResponse) map[string]interface{} {
	t.Helper()
	var decoded map[string]interface{}
	if err := json.Unmarshal(response.Body, &decoded); err != nil {
		t.Fatalf("the answer was not JSON (status %d): %q", response.Status, string(response.Body))
	}
	return decoded
}

// TestApplicationSessionRefusesToMintForAnMFAAccount is the bypass itself: a correct password and a
// correct last-four on an MFA account answers a CHALLENGE, not a session. No token, no stored
// session — the caller holds nothing it can authenticate with until the code is verified.
//
// OBSERVED RED (before the gate existed,
// `go test ./internal -run TestApplicationSessionRefusesToMintForAnMFAAccount -count=1`):
//
//	--- FAIL: TestApplicationSessionRefusesToMintForAnMFAAccount (0.11s)
//	    application_session_mfa_test.go:67: /session answered no mfa_required for an MFA account: map[expires_at:1.792364114e+09 id:user-1789772113926310402-4 token:ms_9f065651dd47... username:mfa-user]
//	    application_session_mfa_test.go:71: /session answered no challenge for an MFA account: map[...]
//	    application_session_mfa_test.go:74: /session handed back a session token for an MFA account before any code was verified
//	    application_session_mfa_test.go:79: /session stored 1 application sessions for an MFA account that has not verified a code
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.200s
func TestApplicationSessionRefusesToMintForAnMFAAccount(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	response := applicationCall(t, server, "POST", "/session", map[string]string{
		"username": user.Username, "password": "securepass123", "phone_last4": "5309",
	})
	if response.Status != 200 {
		t.Fatalf("the ownership gate passed but /session answered %d: %q", response.Status, string(response.Body))
	}
	body := decodeApplication(t, response)
	if body["mfa_required"] != true {
		t.Errorf("/session answered no mfa_required for an MFA account: %v", body)
	}
	challenge, _ := body["challenge"].(string)
	if challenge == "" {
		t.Errorf("/session answered no challenge for an MFA account: %v", body)
	}
	if _, minted := body["token"]; minted {
		t.Errorf("/session handed back a session token for an MFA account before any code was verified")
	}
	var stored int
	server.readForest(func() { stored = len(server.forest.ApplicationSessions) })
	if stored != 0 {
		t.Errorf("/session stored %d application sessions for an MFA account that has not verified a code", stored)
	}
}

// TestApplicationSessionLast4MismatchIsTheSameRefusalAsABadPassword keeps the surface free of an
// MFA-status oracle: a wrong last-four and a wrong password are indistinguishable, so a caller
// holding a stolen password learns nothing about whether the account carries a second factor, and
// nothing about the number. A mismatch also sends NO code — the outbox stays empty.
//
// OBSERVED RED (before the gate existed, same run):
//
//	--- FAIL: TestApplicationSessionLast4MismatchIsTheSameRefusalAsABadPassword (0.19s)
//	    application_session_mfa_test.go:108: a wrong last-four answered 200 "{\"expires_at\":1792364114,\"id\":\"user-...\",\"token\":\"ms_2ec9ccfba2a9...\",\"username\":\"mfa-user\"}\n"; a wrong password answers 401 "Invalid credentials\n"
//	    application_session_mfa_test.go:112: a missing last-four answered 200 "{\"expires_at\":...,\"token\":\"ms_0cbde5f9ef00...\"}\n"; a wrong password answers 401 "Invalid credentials\n"
func TestApplicationSessionLast4MismatchIsTheSameRefusalAsABadPassword(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	badPassword := applicationCall(t, server, "POST", "/session", map[string]string{
		"username": user.Username, "password": "not-the-password", "phone_last4": "5309",
	})
	badLast4 := applicationCall(t, server, "POST", "/session", map[string]string{
		"username": user.Username, "password": "securepass123", "phone_last4": "0000",
	})
	noLast4 := applicationCall(t, server, "POST", "/session", map[string]string{
		"username": user.Username, "password": "securepass123",
	})

	if badLast4.Status != badPassword.Status || string(badLast4.Body) != string(badPassword.Body) {
		t.Errorf("a wrong last-four answered %d %q; a wrong password answers %d %q",
			badLast4.Status, string(badLast4.Body), badPassword.Status, string(badPassword.Body))
	}
	if noLast4.Status != badPassword.Status || string(noLast4.Body) != string(badPassword.Body) {
		t.Errorf("a missing last-four answered %d %q; a wrong password answers %d %q",
			noLast4.Status, string(noLast4.Body), badPassword.Status, string(badPassword.Body))
	}
	var challenges int
	var outbound int
	server.readForest(func() {
		challenges = len(server.forest.MFAChallenges)
		if server.forest.Correspondence != nil {
			outbound = len(server.forest.Correspondence.Outbound)
		}
	})
	if challenges != 0 || outbound != 0 {
		t.Errorf("a refused login left %d challenges and %d queued messages; it must send nothing", challenges, outbound)
	}
}

// TestApplicationSessionMFAMintsWhatTheFirstStepWithheld is the other half: /session/mfa takes the
// challenge and the code and answers EXACTLY what /session used to answer in one step — the same
// shape, id/username/expires_at/token — and the token it hands back authenticates.
//
// OBSERVED RED (before the route existed, same run):
//
//	--- FAIL: TestApplicationSessionMFAMintsWhatTheFirstStepWithheld (0.11s)
//	    application_session_mfa_test.go:146: /session answered with no challenge: map[expires_at:1.792364114e+09 id:user-1789772114224354331-12 token:ms_6bee25b64a9d... username:mfa-user]
func TestApplicationSessionMFAMintsWhatTheFirstStepWithheld(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	first := decodeApplication(t, applicationCall(t, server, "POST", "/session", map[string]string{
		"username": user.Username, "password": "securepass123", "phone_last4": "5309",
	}))
	challenge, _ := first["challenge"].(string)
	if challenge == "" {
		t.Fatalf("/session answered with no challenge: %v", first)
	}
	code := outboundFor(t, server, challengeIDOf(t, server, challenge)).Payload

	response := applicationCall(t, server, "POST", "/session/mfa", map[string]string{"challenge": challenge, "code": code})
	if response.Status != 200 {
		t.Fatalf("/session/mfa answered %d: %q", response.Status, string(response.Body))
	}
	body := decodeApplication(t, response)
	token, _ := body["token"].(string)
	if !strings.HasPrefix(token, "ms_") {
		t.Fatalf("/session/mfa did not mint an application session: %v", body)
	}
	if body["id"] != user.ID || body["username"] != user.Username {
		t.Errorf("/session/mfa answered for %v/%v, want %s/%s", body["id"], body["username"], user.ID, user.Username)
	}
	if expires, _ := body["expires_at"].(float64); expires <= 0 {
		t.Errorf("/session/mfa answered expires_at %v", body["expires_at"])
	}

	authenticated := server.ApplicationCall(ApplicationRequest{Method: "GET", Target: "/session",
		Headers: map[string]string{"Authorization": "Bearer " + token}})
	if authenticated.Status != 200 {
		t.Errorf("the minted token did not authenticate: %d %q", authenticated.Status, string(authenticated.Body))
	}
}

// TestApplicationSessionMFANeedsNoPrincipal proves the route sits OUTSIDE the session guard: a
// caller holding nothing is refused by the CHALLENGE check, not by the middleware. If it were behind
// authMiddleware the answer would be "No token provided" and the second step would be unreachable —
// circular, since the session is what the step exists to obtain.
//
// OBSERVED RED (before the route existed, same run):
//
//	--- FAIL: TestApplicationSessionMFANeedsNoPrincipal (0.08s)
//	    application_session_mfa_test.go:189: /session/mfa answered 404 "404 page not found\n"; want a challenge refusal
func TestApplicationSessionMFANeedsNoPrincipal(t *testing.T) {
	server, _ := newStockServer(t)
	addMFAUser(t, server)

	response := applicationCall(t, server, "POST", "/session/mfa", map[string]string{"challenge": "not-a-challenge", "code": "000000"})
	if response.Status != 401 || !strings.Contains(string(response.Body), "challenge") {
		t.Errorf("/session/mfa answered %d %q; want a challenge refusal", response.Status, string(response.Body))
	}
}

// TestApplicationSessionMFAKeepsTheAttemptBudget: the second step reuses the SAME attempt-limited
// challenge machinery /mfa/verify does, so a stolen challenge cannot be brute-forced against a
// six-digit space through the application surface either.
//
// OBSERVED RED (before the route existed, same run):
//
//	--- FAIL: TestApplicationSessionMFAKeepsTheAttemptBudget (0.12s)
//	    application_session_mfa_test.go:211: /session answered with no challenge: map[expires_at:1.79236412e+09 id:user-1789772120471549292-8 token:ms_60be498b3d62... username:mfa-user]
//	    (with the first step gated but the route missing: wrong code 1 answered 404 "404 page not found\n"; want 401)
func TestApplicationSessionMFAKeepsTheAttemptBudget(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	first := decodeApplication(t, applicationCall(t, server, "POST", "/session", map[string]string{
		"username": user.Username, "password": "securepass123", "phone_last4": "5309",
	}))
	challenge, _ := first["challenge"].(string)
	if challenge == "" {
		t.Fatalf("/session answered with no challenge: %v", first)
	}

	for attempt := 1; attempt <= mfaMaxAttempts; attempt++ {
		response := applicationCall(t, server, "POST", "/session/mfa", map[string]string{"challenge": challenge, "code": "000001"})
		if response.Status != 401 {
			t.Fatalf("wrong code %d answered %d %q; want 401", attempt, response.Status, string(response.Body))
		}
		if attempt == mfaMaxAttempts && !strings.Contains(string(response.Body), "Too many attempts") {
			t.Errorf("the last attempt answered %q; want the challenge destroyed", string(response.Body))
		}
	}
	var challenges int
	server.readForest(func() { challenges = len(server.forest.MFAChallenges) })
	if challenges != 0 {
		t.Errorf("%d challenges survived the attempt budget", challenges)
	}
}
