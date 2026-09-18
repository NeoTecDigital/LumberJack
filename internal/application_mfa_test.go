package internal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// addMFAUser plants a user with a known password, a formatted phone and MFA on, and returns the copy
// findUserByName would hand a login. The phone is deliberately formatted (spaces, punctuation, a
// country code) so the last-four gate is tested against digits, not against the stored string.
func addMFAUser(t *testing.T, server *Server) core.User {
	t.Helper()
	user := core.User{
		ID:         core.GenerateUserID(),
		Username:   "mfa-user",
		Phone:      "+1 (555) 867-5309",
		MFAEnabled: true,
	}
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

// challengeIDOf reads the challenge id out of an mfa_pending bearer, so a test can reach the store
// record the token stands for.
func challengeIDOf(t *testing.T, server *Server, token string) string {
	t.Helper()
	claims, err := server.parseMFAChallengeToken(token)
	if err != nil {
		t.Fatalf("the challenge token did not validate: %v", err)
	}
	return claims.ChallengeID
}

// outboundFor returns the enqueued external item for a challenge, which is the only place the
// plaintext code exists.
func outboundFor(t *testing.T, server *Server, challengeID string) core.OutboundMessage {
	t.Helper()
	item, ok := server.forest.Correspondence.Outbound[challengeID]
	if !ok {
		t.Fatalf("no outbound item was enqueued for challenge %s", challengeID)
	}
	return item
}

// TestMFAChallengeStoresHashAndEnqueuesPlaintext is the store's central claim: the forest keeps only
// a keyed hash of the code, while the plaintext lives ONLY on the outbox for delivery, tagged so a
// dispatcher can route it.
//
// OBSERVED RED (beginMFAChallenge storing CodeHash: code instead of the hash,
// `go test ./internal -run TestMFAChallengeStoresHashAndEnqueuesPlaintext -count=1`):
//
//	--- FAIL: TestMFAChallengeStoresHashAndEnqueuesPlaintext (0.08s)
//	    application_mfa_test.go:86: the stored value equals the plaintext code: the code is in the state file
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.078s
func TestMFAChallengeStoresHashAndEnqueuesPlaintext(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)

	stored, ok := server.forest.MFAChallenges[challengeID]
	if !ok {
		t.Fatalf("no challenge was stored for id %s", challengeID)
	}
	out := outboundFor(t, server, challengeID)

	if out.Payload == stored.CodeHash {
		t.Fatal("the stored value equals the plaintext code: the code is in the state file")
	}
	if stored.CodeHash != server.mfaCodeHash(out.Payload) {
		t.Fatal("the stored hash is not the keyed hash of the enqueued code")
	}
	if len(out.Payload) != 6 {
		t.Fatalf("the code is not six digits: %q", out.Payload)
	}
	if out.Channel != "sms" || out.Purpose != "mfa" {
		t.Fatalf("the outbound item carries no MFA/SMS routing marker: %+v", out)
	}
	if out.To != user.Phone {
		t.Fatalf("the outbound item is addressed to %q, not the user's phone %q", out.To, user.Phone)
	}
	if stored.Attempts != 0 {
		t.Fatalf("a fresh challenge starts with %d attempts, want 0", stored.Attempts)
	}
}

// TestMFAVerifyAcceptsCorrectCodeOnce proves the happy path and single use: the right code mints a
// full session+refresh pair, and the challenge is gone afterward so the same code cannot be replayed.
//
// OBSERVED RED (verifyMFAChallenge returning nil,nil without deleting or minting,
// `go test ./internal -run TestMFAVerifyAcceptsCorrectCodeOnce -count=1`):
//
//	--- FAIL: TestMFAVerifyAcceptsCorrectCodeOnce (0.08s)
//	    application_mfa_test.go:128: verify returned no token pair for the correct code: <nil>
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.077s
func TestMFAVerifyAcceptsCorrectCodeOnce(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)
	code := outboundFor(t, server, challengeID).Payload

	pair, err := server.verifyMFAChallenge(token, code)
	if err != nil || pair == nil {
		t.Fatalf("verify returned no token pair for the correct code: %v", err)
	}
	if pair.SessionToken == "" || pair.RefreshToken == "" {
		t.Fatalf("verify returned an incomplete pair: %+v", pair)
	}
	if tokenType := tokenClaimString(t, pair.SessionToken, "token_type"); tokenType != "session" {
		t.Fatalf("verify minted a %q token, want a session", tokenType)
	}
	if _, ok := server.forest.MFAChallenges[challengeID]; ok {
		t.Fatal("the challenge survived a successful verify: it can be replayed")
	}
	if _, err := server.verifyMFAChallenge(token, code); err == nil {
		t.Fatal("a second verify with the same code and token succeeded")
	}
}

// TestMFAVerifyRejectsWrongCodeAndCountsIt proves a wrong guess is refused, the attempt is counted,
// and the counting is DURABLE — the challenge remains for the next try rather than being reset.
//
// OBSERVED RED (verifyMFAChallenge skipping the constant-time compare and always succeeding,
// `go test ./internal -run TestMFAVerifyRejectsWrongCodeAndCountsIt -count=1`):
//
//	--- FAIL: TestMFAVerifyRejectsWrongCodeAndCountsIt (0.08s)
//	    application_mfa_test.go:166: a wrong code was accepted
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.079s
func TestMFAVerifyRejectsWrongCodeAndCountsIt(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)
	wrong := wrongCode(outboundFor(t, server, challengeID).Payload)

	if _, err := server.verifyMFAChallenge(token, wrong); err == nil {
		t.Fatal("a wrong code was accepted")
	}
	stored, ok := server.forest.MFAChallenges[challengeID]
	if !ok {
		t.Fatal("a single wrong guess destroyed the challenge; the user cannot retry")
	}
	if stored.Attempts != 1 {
		t.Fatalf("the wrong guess was counted as %d attempts, want 1", stored.Attempts)
	}
}

// TestMFAVerifyLocksOutAfterMaxAttempts proves the guess budget: on the Nth wrong code the challenge
// is destroyed, and even the correct code cannot complete it afterward.
//
// OBSERVED RED (the lockout `delete` in verifyMFAChallenge's mismatch branch disabled with `if false`,
// `go test ./internal -run TestMFAVerifyLocksOutAfterMaxAttempts -count=1`):
//
//	--- FAIL: TestMFAVerifyLocksOutAfterMaxAttempts (0.08s)
//	    application_mfa_test.go:205: the challenge was not locked out after the attempt budget
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.079s
func TestMFAVerifyLocksOutAfterMaxAttempts(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)
	code := outboundFor(t, server, challengeID).Payload
	wrong := wrongCode(code)

	for i := 0; i < mfaMaxAttempts; i++ {
		if _, err := server.verifyMFAChallenge(token, wrong); err == nil {
			t.Fatalf("wrong guess %d was accepted", i+1)
		}
	}
	if _, ok := server.forest.MFAChallenges[challengeID]; ok {
		t.Fatal("the challenge was not locked out after the attempt budget")
	}
	if _, err := server.verifyMFAChallenge(token, code); err == nil {
		t.Fatal("the correct code completed a locked-out challenge")
	}
}

// TestMFAVerifyRejectsExpiredChallenge proves the TTL: a challenge past its expiry is refused and
// swept, even with the right code.
//
// OBSERVED RED (verifyMFAChallenge's expiry guard inverted, `<= now` to `>= now`,
// `go test ./internal -run TestMFAVerifyRejectsExpiredChallenge -count=1`):
//
//	--- FAIL: TestMFAVerifyRejectsExpiredChallenge (0.08s)
//	    application_mfa_test.go:238: an expired challenge accepted the code
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.078s
func TestMFAVerifyRejectsExpiredChallenge(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)
	code := outboundFor(t, server, challengeID).Payload

	expired := server.forest.MFAChallenges[challengeID]
	expired.ExpiresAt = 1 // 1970: safely in the past
	server.forest.MFAChallenges[challengeID] = expired

	if _, err := server.verifyMFAChallenge(token, code); err == nil {
		t.Fatal("an expired challenge accepted the code")
	}
	if _, ok := server.forest.MFAChallenges[challengeID]; ok {
		t.Fatal("an expired challenge was not swept on verify")
	}
}

// TestLoginWithoutMFAIsByteIdentical is the promise that a password-only login is untouched. The
// response carries exactly the two token keys and no MFA field, and the session token's claims carry
// no challenge_id — the omitempty tag means the signed bytes are what they were before MFA existed.
//
// OBSERVED RED (TokenClaims.ChallengeID tagged `json:"challenge_id"` without omitempty,
// `go test ./internal -run TestLoginWithoutMFAIsByteIdentical -count=1`):
//
//	--- FAIL: TestLoginWithoutMFAIsByteIdentical (0.11s)
//	    application_mfa_test.go:278: a password-only session token carries challenge_id; the claims are not byte-identical
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.115s
func TestLoginWithoutMFAIsByteIdentical(t *testing.T) {
	server, _ := newStockServer(t)
	user := core.User{ID: core.GenerateUserID(), Username: "plain-user"}
	if err := user.SetPassword("securepass123"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := server.changeForest(func() error {
		return server.forest.AssignUser(user, core.ReadPermission)
	}); err != nil {
		t.Fatalf("AssignUser: %v", err)
	}

	body := login(t, server, map[string]interface{}{"username": "plain-user", "password": "securepass123"})
	if code := body.status; code != http.StatusOK {
		t.Fatalf("password-only login answered %d", code)
	}
	if keys := sortedKeys(body.json); strings.Join(keys, ",") != "refresh_token,session_token" {
		t.Fatalf("the login response keys are %v, not the two token keys", keys)
	}
	claims := tokenClaimKeys(t, body.json["session_token"].(string))
	for _, key := range claims {
		if key == "challenge_id" {
			t.Fatal("a password-only session token carries challenge_id; the claims are not byte-identical")
		}
	}
}

// TestLoginWithMFARefusesWrongLast4PreSend is the ownership gate: a wrong last-four is refused with
// the same credential error a bad password gets, and NOTHING is sent — no challenge, no outbound.
//
// OBSERVED RED (the phoneLast4Matches gate disabled with `if false`, so a wrong last-four falls
// through to the challenge path, `go test ./internal -run TestLoginWithMFARefusesWrongLast4PreSend -count=1`):
//
//	--- FAIL: TestLoginWithMFARefusesWrongLast4PreSend (0.11s)
//	    application_mfa_test.go:301: a wrong last-four answered 200, want 401
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.114s
func TestLoginWithMFARefusesWrongLast4PreSend(t *testing.T) {
	server, _ := newStockServer(t)
	addMFAUser(t, server)

	body := login(t, server, map[string]interface{}{
		"username": "mfa-user", "password": "securepass123", "phone_last4": "0000",
	})
	if body.status != http.StatusUnauthorized {
		t.Fatalf("a wrong last-four answered %d, want 401", body.status)
	}
	if len(server.forest.MFAChallenges) != 0 {
		t.Fatal("a code was generated despite the wrong last-four")
	}
	if server.forest.Correspondence != nil && len(server.forest.Correspondence.Outbound) != 0 {
		t.Fatal("an outbound item was enqueued despite the wrong last-four: a code was sent")
	}
}

// TestLoginWithMFAMintsChallengeOnCorrectLast4 is the send half through the handler: password plus
// the right last-four answers a challenge (never a session), stores only a hash, and enqueues the
// code. The wrong-password path must still 401 before any of this.
//
// OBSERVED RED (handleLogin's `if foundUser.MFAEnabled` branch commented out so it fell through to
// generateTokenPair, `go test ./internal -run TestLoginWithMFAMintsChallengeOnCorrectLast4 -count=1`):
//
//	--- FAIL: TestLoginWithMFAMintsChallengeOnCorrectLast4 (0.15s)
//	    application_mfa_test.go:339: an MFA login returned a session_token instead of a challenge
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.152s
func TestLoginWithMFAMintsChallengeOnCorrectLast4(t *testing.T) {
	server, _ := newStockServer(t)
	addMFAUser(t, server)

	if bad := login(t, server, map[string]interface{}{
		"username": "mfa-user", "password": "wrongpass", "phone_last4": "5309",
	}); bad.status != http.StatusUnauthorized {
		t.Fatalf("a wrong password on an MFA account answered %d, want 401", bad.status)
	}

	body := login(t, server, map[string]interface{}{
		"username": "mfa-user", "password": "securepass123", "phone_last4": "5309",
	})
	if body.status != http.StatusOK {
		t.Fatalf("a correct MFA login answered %d", body.status)
	}
	if _, ok := body.json["session_token"]; ok {
		t.Fatal("an MFA login returned a session_token instead of a challenge")
	}
	if required, _ := body.json["mfa_required"].(bool); !required {
		t.Fatalf("the MFA login did not signal mfa_required: %v", body.json)
	}
	challenge, _ := body.json["challenge"].(string)
	if challenge == "" {
		t.Fatal("the MFA login returned no challenge token")
	}
	challengeID := challengeIDOf(t, server, challenge)
	stored, ok := server.forest.MFAChallenges[challengeID]
	if !ok || stored.CodeHash == "" {
		t.Fatal("no hashed challenge was stored for the minted challenge")
	}
	out := outboundFor(t, server, challengeID)
	if stored.CodeHash != server.mfaCodeHash(out.Payload) {
		t.Fatal("the stored hash does not match the enqueued code")
	}
}

// ---- small helpers, so the tests above read as assertions ----

type loginResult struct {
	status int
	json   map[string]interface{}
}

func login(t *testing.T, server *Server, payload map[string]interface{}) loginResult {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode login body: %v", err)
	}
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleLogin(rec, req)
	result := loginResult{status: rec.Code}
	if body := rec.Body.Bytes(); len(bytes.TrimSpace(body)) > 0 && json.Valid(body) {
		_ = json.Unmarshal(body, &result.json)
	}
	return result
}

// wrongCode returns a six-digit code that is not the argument.
func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}

// tokenClaimKeys decodes a JWT's payload segment and returns the raw claim keys, which is how the
// byte-identity test proves an absent field is absent rather than merely empty.
func tokenClaimKeys(t *testing.T, token string) []string {
	t.Helper()
	claims := decodeClaims(t, token)
	keys := make([]string, 0, len(claims))
	for key := range claims {
		keys = append(keys, key)
	}
	return keys
}

func tokenClaimString(t *testing.T, token, key string) string {
	t.Helper()
	claims := decodeClaims(t, token)
	value, _ := claims[key].(string)
	return value
}

func decodeClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}
