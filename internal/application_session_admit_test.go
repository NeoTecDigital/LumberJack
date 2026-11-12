// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/internal/admission"
)

// POST /session/admit is dispatched by ApplicationCall, not the mux, so these go through
// ApplicationCall: a handler nothing routes to fails here exactly as a missing one does.

const (
	admitIssuer   = "activity-personal:installation"
	admitAudience = "momentum-personal:installation"
	admitKeyID    = "personal-test"
	admitOwner    = "bootstrap-owner-0123456789abcdef"
	admitName     = "owner@example.test"
)

var ownerProfile = sessionProfile{Username: admitName, Email: admitName}

type admitFixture struct {
	t      *testing.T
	server *Server
	key    ed25519.PrivateKey
	serial int
}

func newAdmitFixture(t *testing.T) *admitFixture {
	t.Helper()
	t.Setenv("MOMENTUM_REQUIRE_MFA", "true")
	server, _ := newStockServer(t)
	key := ed25519.NewKeyFromSeed(append(make([]byte, 31), 7))
	config := SessionAdmissionConfig{KeyID: admitKeyID, PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Issuer: admitIssuer, Audience: admitAudience}
	if err := server.ConfigureSessionAdmission(config); err != nil {
		t.Fatalf("ConfigureSessionAdmission: %v", err)
	}
	return &admitFixture{t: t, server: server, key: key}
}

func profileBytes(t *testing.T, profile sessionProfile) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"email": profile.Email, "username": profile.Username})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// claims is a valid admission for principal under this profile, with a command nothing has spent yet.
func (f *admitFixture) claims(principal string, profile sessionProfile) admission.Claims {
	f.serial++
	digest := sha256.Sum256(profileBytes(f.t, profile))
	return admission.Claims{Version: 1, Issuer: admitIssuer, Audience: admitAudience, PrincipalID: principal, SessionID: "source-session",
		Scope: admission.Scope{AccountID: "personal-account", Product: admission.SessionProduct}, GrantRevision: "sha256:grant",
		ResourceRevision: "personal-session/0.1", ResourceID: principal, Operation: admission.SessionOperation,
		CommandID: "command-" + string(rune('a'+f.serial%26)) + hex.EncodeToString([]byte{byte(f.serial)}), BodySHA256: hex.EncodeToString(digest[:]),
		ExpiresAt: time.Now().Unix() + 45, BarrierVersion: 1}
}

// signedString is the opaque admission string: the signed envelope and the profile bytes beside it.
func (f *admitFixture) signedString(claims admission.Claims, profile []byte, key ed25519.PrivateKey) string {
	f.t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		f.t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		f.t.Fatal(err)
	}
	if raw, err = json.Marshal(value); err != nil {
		f.t.Fatal(err)
	}
	envelope, err := json.Marshal(admission.Envelope{KeyID: admitKeyID, Payload: base64.RawURLEncoding.EncodeToString(raw),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))})
	if err != nil {
		f.t.Fatal(err)
	}
	return `{"envelope":` + string(envelope) + `,"profile":` + string(profile) + `}`
}

// signed is a whole valid admission for principal under this profile.
func (f *admitFixture) signed(principal string, profile sessionProfile) string {
	f.t.Helper()
	return f.signedString(f.claims(principal, profile), profileBytes(f.t, profile), f.key)
}

func (f *admitFixture) post(envelope string) ApplicationResponse {
	f.t.Helper()
	return applicationCall(f.t, f.server, "POST", "/session/admit", map[string]string{"admission": envelope})
}

// admit presents a valid admission for principal and answers the session it was given.
func (f *admitFixture) admit(principal string) (string, map[string]interface{}) {
	f.t.Helper()
	return f.admitAs(principal, sessionProfile{Username: principal + "@example.test", Email: principal + "@example.test"})
}

func (f *admitFixture) admitAs(principal string, profile sessionProfile) (string, map[string]interface{}) {
	f.t.Helper()
	response := f.post(f.signed(principal, profile))
	if response.Status != 200 {
		f.t.Fatalf("admission refused: %d %q", response.Status, response.Body)
	}
	body := decodeApplication(f.t, response)
	token, _ := body["token"].(string)
	if !strings.HasPrefix(token, "ms_") {
		f.t.Fatalf("no ms_ token in the answer: %v", body)
	}
	return token, body
}

func (f *admitFixture) call(method, target, token string) ApplicationResponse {
	f.t.Helper()
	return f.server.ApplicationCall(ApplicationRequest{Method: method, Target: target, Headers: map[string]string{"Authorization": "Bearer " + token}})
}

func (f *admitFixture) userCount() int {
	count := 0
	f.server.readForest(func() { count = len(f.server.forest.Users) })
	return count
}

func (f *admitFixture) sessionCount() int {
	count := 0
	f.server.readForest(func() { count = len(f.server.forest.ApplicationSessions) })
	return count
}

func TestSessionAdmitMintsADelegatedSessionForANewUser(t *testing.T) {
	f := newAdmitFixture(t)
	token, body := f.admitAs(admitOwner, ownerProfile)
	now := time.Now().Unix()
	expires, _ := body["expires_at"].(float64)
	if int64(expires) < now+590 || int64(expires) > now+600 {
		t.Fatalf("the lease is not ten minutes: %v (now %d)", body["expires_at"], now)
	}
	if body["id"] != admitOwner || body["username"] != admitName {
		t.Fatalf("the session names the wrong account: %v", body)
	}
	var session core.ApplicationSession
	var user *core.User
	admin := true
	f.server.readForest(func() {
		session = f.server.forest.ApplicationSessions[f.server.sessionHash(token)]
		user, _ = f.server.forest.GetUserProfile(admitOwner)
		admin = f.server.forest.CheckPermission(admitOwner, core.AdminPermission)
	})
	if !session.Delegated || session.SourceSession != "source-session" || session.UserID != admitOwner {
		t.Fatalf("the stored session is not delegated from its source: %+v", session)
	}
	if session.ExpiresAt != session.CreatedAt+delegatedSessionTTL || session.MFAAt != 0 {
		t.Fatalf("a delegated session has its own lease and no factor stamp: %+v", session)
	}
	if user == nil || user.ID != admitOwner || user.Password != "" || user.Username != admitName || user.Email != admitName {
		t.Fatalf("the ensured account is wrong: %+v", user)
	}
	if len(user.Permissions) != 1 || user.Permissions[0] != core.ReadPermission || admin {
		t.Fatalf("an ensured account gets root read and nothing more: %+v admin=%v", user.Permissions, admin)
	}
	if got := f.call("GET", "/workspace", token); got.Status != 200 {
		t.Fatalf("the delegated session cannot read its workspace: %d %q", got.Status, got.Body)
	}
	before := f.userCount()
	f.admitAs(admitOwner, ownerProfile)
	if f.userCount() != before {
		t.Fatalf("a second admission created the account again")
	}
}

func TestSessionAdmitRefusals(t *testing.T) {
	f := newAdmitFixture(t)
	stranger := ed25519.NewKeyFromSeed(append(make([]byte, 31), 9))
	cases := map[string]func(*admission.Claims) ed25519.PrivateKey{
		"forged signature":   func(c *admission.Claims) ed25519.PrivateKey { return stranger },
		"wrong issuer":       func(c *admission.Claims) ed25519.PrivateKey { c.Issuer = "activity-personal:other"; return f.key },
		"wrong audience":     func(c *admission.Claims) ed25519.PrivateKey { c.Audience = "momentum-personal:other"; return f.key },
		"expired":            func(c *admission.Claims) ed25519.PrivateKey { c.ExpiresAt = time.Now().Unix() - 1; return f.key },
		"over-long lifetime": func(c *admission.Claims) ed25519.PrivateKey { c.ExpiresAt = time.Now().Unix() + 120; return f.key },
		"wrong operation":    func(c *admission.Claims) ed25519.PrivateKey { c.Operation = "manifest.write"; return f.key },
		"wrong product":      func(c *admission.Claims) ed25519.PrivateKey { c.Scope.Product = "manifest"; return f.key },
		"workspace scoped":   func(c *admission.Claims) ed25519.PrivateKey { c.Scope.WorkspaceID = "workspace"; return f.key },
		"another resource":   func(c *admission.Claims) ed25519.PrivateKey { c.ResourceID = "other"; return f.key },
		"wrong body digest":  func(c *admission.Claims) ed25519.PrivateKey { c.BodySHA256 = strings.Repeat("0", 64); return f.key },
	}
	users, sessions := f.userCount(), f.sessionCount()
	for name, change := range cases {
		claims := f.claims(admitOwner, ownerProfile)
		key := change(&claims)
		if got := f.post(f.signedString(claims, profileBytes(t, ownerProfile), key)); got.Status != 401 {
			t.Errorf("%s: answered %d %q", name, got.Status, got.Body)
		}
	}
	for name, body := range map[string]any{"empty admission": map[string]string{"admission": ""}, "no admission": map[string]string{},
		"not an envelope": map[string]string{"admission": "{}"}, "an extra field": map[string]string{"admission": "{}", "principal": admitOwner}} {
		if got := applicationCall(t, f.server, "POST", "/session/admit", body); got.Status != 401 {
			t.Errorf("%s: answered %d %q", name, got.Status, got.Body)
		}
	}
	if f.userCount() != users || f.sessionCount() != sessions {
		t.Fatalf("a refusal left state behind: users %d -> %d, sessions %d -> %d", users, f.userCount(), sessions, f.sessionCount())
	}
}

func TestSessionAdmitIsRefusedWhenNotConfigured(t *testing.T) {
	server, _ := newStockServer(t)
	f := &admitFixture{t: t, server: server, key: ed25519.NewKeyFromSeed(make([]byte, 32))}
	if got := f.post(f.signed(admitOwner, ownerProfile)); got.Status != 401 {
		t.Fatalf("an unconfigured engine answered %d %q", got.Status, got.Body)
	}
}

func TestSessionAdmitCommandIsSingleUse(t *testing.T) {
	f := newAdmitFixture(t)
	signed := f.signed(admitOwner, ownerProfile)
	if got := f.post(signed); got.Status != 200 {
		t.Fatalf("the first use was refused: %d %q", got.Status, got.Body)
	}
	sessions := f.sessionCount()
	if got := f.post(signed); got.Status != 401 {
		t.Fatalf("the replay answered %d %q", got.Status, got.Body)
	}
	if f.sessionCount() != sessions {
		t.Fatalf("the replay minted a session")
	}
}

func TestSessionAdmitForgetsSpentCommandsOnlyPastTheirExpiry(t *testing.T) {
	f := newAdmitFixture(t)
	f.admit(admitOwner)
	now := time.Now().Unix()
	if err := f.server.changeForest(func() error {
		f.server.forest.AdmittedCommands["stale"] = now - 1
		f.server.forest.AdmittedCommands["alive"] = now + 30
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.admit(admitOwner)
	var stale, alive bool
	f.server.readForest(func() {
		_, stale = f.server.forest.AdmittedCommands["stale"]
		_, alive = f.server.forest.AdmittedCommands["alive"]
	})
	if stale || !alive {
		t.Fatalf("the ledger swept wrongly: stale kept=%v alive kept=%v", stale, alive)
	}
}

func TestSessionAdmitNeverCreatesInTheEngineNamespace(t *testing.T) {
	f := newAdmitFixture(t)
	users := f.userCount()
	for _, principal := range []string{"user-1234-1", SystemUserID, "a/b", "../escape", ".hidden"} {
		if got := f.post(f.signed(principal, ownerProfile)); got.Status != 401 {
			t.Errorf("%s: answered %d %q", principal, got.Status, got.Body)
		}
	}
	if f.userCount() != users {
		t.Fatalf("a refused principal was created")
	}
	migrated := addPasswordUser(t, f.server, "migrated", "fixture-password")
	if !strings.HasPrefix(migrated.ID, engineUserNamespace) {
		t.Fatalf("the fixture is not in the engine's namespace: %s", migrated.ID)
	}
	named := sessionProfile{Username: "migrated", Email: "migrated@example.test"}
	if token, body := f.admitAs(migrated.ID, named); body["username"] != "migrated" || f.call("GET", "/principal", token).Status != 200 {
		t.Fatalf("a migrated account was not admitted to itself: %v", body)
	}
}

func TestSessionAdmitRefusesAnAdministrator(t *testing.T) {
	f := newAdmitFixture(t)
	operator := core.User{ID: "operator-principal", Username: "operator"}
	if err := f.server.changeForest(func() error { return f.server.forest.AssignUser(operator, core.AdminPermission) }); err != nil {
		t.Fatal(err)
	}
	if got := f.post(f.signed(operator.ID, ownerProfile)); got.Status != 401 {
		t.Errorf("an administrator answered %d %q", got.Status, got.Body)
	}
}

func TestOnlyADelegatedSessionSkipsTheFactorCheck(t *testing.T) {
	f := newAdmitFixture(t)
	normal := addPasswordUser(t, f.server, "no-factors", "fixture-password")
	minted, _, err := f.server.mintApplicationSession(normal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid := f.server.applicationSession(minted); valid {
		t.Fatalf("a normal session without factors passed the MFA check")
	}
	if got := f.call("GET", "/principal", minted); got.Status != 401 {
		t.Fatalf("a normal session without factors answered %d", got.Status)
	}
	delegated, _ := f.admit(admitOwner)
	if _, valid := f.server.applicationSession(delegated); !valid {
		t.Fatalf("a delegated session failed the MFA check")
	}
	if got := f.call("GET", "/principal", delegated); got.Status != 200 {
		t.Fatalf("a delegated session answered %d %q", got.Status, got.Body)
	}
}

func TestDelegatedSessionEndsAtItsLeaseWhateverTheActivity(t *testing.T) {
	f := newAdmitFixture(t)
	token, _ := f.admit(admitOwner)
	key := f.server.sessionHash(token)
	if got := f.call("POST", "/session/activity", token); got.Status != 200 {
		t.Fatalf("activity refused: %d %q", got.Status, got.Body)
	}
	var created, deadline int64
	f.server.readForest(func() {
		held := f.server.forest.ApplicationSessions[key]
		created, deadline = held.CreatedAt, applicationSessionDeadline(held)
	})
	if deadline != created+delegatedSessionTTL {
		t.Fatalf("activity moved the lease: created %d deadline %d", created, deadline)
	}
	if err := f.server.changeForest(func() error {
		held := f.server.forest.ApplicationSessions[key]
		held.ExpiresAt = time.Now().Unix() - 1
		f.server.forest.ApplicationSessions[key] = held
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := f.call("GET", "/principal", token); got.Status != 401 {
		t.Fatalf("an expired delegated session answered %d", got.Status)
	}
}

func TestDeleteEndsTheDelegatedSessionAndItsFamily(t *testing.T) {
	f := newAdmitFixture(t)
	first, _ := f.admit(admitOwner)
	second, _ := f.admit(admitOwner)
	named := sessionProfile{Username: admitOwner + "@example.test", Email: admitOwner + "@example.test"}
	other := f.claims(admitOwner, named)
	other.SessionID = "another-device"
	response := f.post(f.signedString(other, profileBytes(t, named), f.key))
	if response.Status != 200 {
		t.Fatalf("the second device was refused: %d", response.Status)
	}
	third, _ := decodeApplication(t, response)["token"].(string)
	if got := f.call("DELETE", "/session", second); got.Status != 200 {
		t.Fatalf("DELETE answered %d %q", got.Status, got.Body)
	}
	for name, token := range map[string]string{"the session": second, "its renewed predecessor": first} {
		if got := f.call("GET", "/principal", token); got.Status != 401 {
			t.Errorf("%s answered %d after DELETE", name, got.Status)
		}
	}
	if got := f.call("GET", "/principal", third); got.Status != 200 {
		t.Fatalf("another source session was signed out too: %d", got.Status)
	}
}

func TestDelegatedAccountHasNoPasswordDoorAndCannotBeLockedOut(t *testing.T) {
	f := newAdmitFixture(t)
	f.admit(admitOwner)
	for attempt := 0; attempt < loginFailureLimit+2; attempt++ {
		for _, password := range []string{"", "any-guess-at-all"} {
			body := map[string]string{"username": admitOwner + "@example.test", "password": password}
			for _, target := range []string{"/session", "/login"} {
				if got := applicationCall(t, f.server, "POST", target, body); got.Status != 401 {
					t.Fatalf("%s with %q answered %d %q", target, password, got.Status, got.Body)
				}
			}
		}
	}
	var user *core.User
	f.server.readForest(func() { user, _ = f.server.forest.GetUserProfile(admitOwner) })
	if user.FailedLogins != 0 || user.LockedUntil != 0 {
		t.Fatalf("a stranger's guesses counted against an account with no password: %+v", user)
	}
	f.admit(admitOwner)
}

func TestDelegatedSessionIsRefusedAtTheFactorRoutes(t *testing.T) {
	f := newAdmitFixture(t)
	token, _ := f.admit(admitOwner)
	calls := []struct{ method, target, body string }{
		{"GET", "/account/security", ""},
		{"POST", "/account/security", `{"operation":"begin_factor","method":"totp_enroll"}`},
		{"POST", "/account/security", `{"operation":"reauthenticate","method":"totp"}`},
		{"POST", "/account/webauthn/begin", `{}`},
		{"POST", "/account/webauthn/finish", `{}`},
		{"POST", "/account/qr/approve", `{}`},
	}
	for _, call := range calls {
		got := f.server.ApplicationCall(ApplicationRequest{Method: call.method, Target: call.target, Body: []byte(call.body),
			Headers: map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}})
		if got.Status != 403 {
			t.Errorf("%s %s answered %d %q", call.method, call.target, got.Status, got.Body)
		}
	}
}

func TestDelegatedAccountsCannotReadEachOthersWorkspace(t *testing.T) {
	f := newAdmitFixture(t)
	first, _ := f.admit(admitOwner)
	second, _ := f.admit("bootstrap-journey-second")
	initialize := func(token string) string {
		t.Helper()
		var view struct {
			Nodes []struct {
				Path string `json:"path"`
			} `json:"nodes"`
		}
		if err := json.Unmarshal(f.call("GET", "/workspace", token).Body, &view); err != nil || len(view.Nodes) == 0 {
			t.Fatalf("no workspace root to initialize from: %v", err)
		}
		command, _ := json.Marshal(map[string]string{"command": "initialize", "path": view.Nodes[0].Path, "client_id": "home"})
		got := f.server.ApplicationCall(ApplicationRequest{Method: "POST", Target: "/workspace/commands", Body: command,
			Headers: map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}})
		if got.Status != 200 {
			t.Fatalf("initialize answered %d %q", got.Status, got.Body)
		}
		return string(got.Body)
	}
	initialize(first)
	initialize(second)
	home := "personal-" + admitOwner
	workspace := f.call("GET", "/workspace", second)
	if workspace.Status != 200 || strings.Contains(string(workspace.Body), home) {
		t.Fatalf("the second account's workspace shows the first's home: %d %q", workspace.Status, workspace.Body)
	}
	if !strings.Contains(string(f.call("GET", "/workspace", first).Body), home) {
		t.Fatalf("the first account cannot see its own home")
	}
	if got := f.call("GET", "/nodes/"+home, second); got.Status == 200 {
		t.Fatalf("the second account read the first's home directly: %q", got.Body)
	}
}

func TestSessionAdmitPassesTheChangeDeliveryBacklog(t *testing.T) {
	f := newAdmitFixture(t)
	if err := f.server.changeForest(func() error {
		state := f.server.correspondenceState()
		for index := 0; index < 4096; index++ {
			state.Pending[hex.EncodeToString([]byte{byte(index), byte(index >> 8)})] = core.CorrespondenceChange{ID: "held"}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.admit(admitOwner)
}

func TestSessionAdmissionConfigurationIsStrictAndOneShot(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey))
	valid := `{"keyId":"k","publicKey":"` + key + `","issuer":"i","audience":"a"}`
	if _, err := DecodeSessionAdmissionConfig([]byte(valid)); err != nil {
		t.Fatalf("a valid configuration was refused: %v", err)
	}
	for name, body := range map[string]string{
		"not json": `nope`, "null": `null`, "empty": `{}`,
		"missing audience": `{"keyId":"k","publicKey":"` + key + `","issuer":"i"}`,
		"extra field":      `{"keyId":"k","publicKey":"` + key + `","issuer":"i","audience":"a","seed":"x"}`,
		"duplicate field":  `{"keyId":"k","keyId":"j","publicKey":"` + key + `","issuer":"i","audience":"a"}`,
		"short key":        `{"keyId":"k","publicKey":"AAAA","issuer":"i","audience":"a"}`,
		"not base64":       `{"keyId":"k","publicKey":"***","issuer":"i","audience":"a"}`,
		"bad issuer":       `{"keyId":"k","publicKey":"` + key + `","issuer":"has space","audience":"a"}`,
	} {
		if _, err := DecodeSessionAdmissionConfig([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	server, _ := newStockServer(t)
	config, err := DecodeSessionAdmissionConfig([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ConfigureSessionAdmission(config); err != nil {
		t.Fatal(err)
	}
	if err := server.ConfigureSessionAdmission(config); err == nil {
		t.Fatalf("a second configuration replaced the first")
	}
}
