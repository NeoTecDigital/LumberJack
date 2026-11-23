// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/NeoTecDigital/LumberJack/extension"
)

// Request authentication, the /principal projection and configuration parts through the extension
// seams (docs/extension-api.md §4.4, §4.7), with a test authenticator and no product code.

const testCredentialHeader = "X-Test-Credential"

type headerAuthenticator struct {
	userID     string
	projection map[string]any
	configured map[string]json.RawMessage
}

func (a *headerAuthenticator) Close(context.Context) error { return nil }

func (a *headerAuthenticator) AuthenticateRequest(r *http.Request) (extension.Principal, extension.Claim) {
	switch r.Header.Get(testCredentialHeader) {
	case "":
		return extension.Principal{}, extension.NotMine
	case "good":
		return extension.Principal{UserID: a.userID, Projection: a.projection}, extension.Accepted
	}
	return extension.Principal{}, extension.Refused
}

func (a *headerAuthenticator) MalformedHeaders(headers map[string]string) bool {
	return headers[testCredentialHeader] == "malformed"
}

func (a *headerAuthenticator) Configure(part string, raw json.RawMessage) error {
	if string(raw) == `"refuse"` {
		return errors.New("refused")
	}
	a.configured[part] = raw
	return nil
}

// withAuthenticator is a stock server with one attached header authenticator acting as its admin.
func withAuthenticator(t *testing.T, projection map[string]any) (*Server, *headerAuthenticator) {
	t.Helper()
	server, _ := newStockServer(t)
	authenticator := &headerAuthenticator{userID: adminID(t, server), projection: projection, configured: map[string]json.RawMessage{}}
	ext := testExtension{spec: extension.Spec{Name: "header-auth", ConfigParts: []string{"header"}},
		attach: func(extension.Host) (extension.Instance, error) { return authenticator, nil }}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
	return server, authenticator
}

func forestWith(t *testing.T, server *Server, credential, bearer string) int {
	t.Helper()
	request := httptest.NewRequest("GET", "/forest", nil)
	if credential != "" {
		request.Header.Set(testCredentialHeader, credential)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	return serve(t, server, request).Code
}

// An accepted claim authenticates, a refused one is 401 even beside a valid bearer, and a request
// the authenticator does not claim falls through to the engine's own bearer check.
func TestAuthenticatorRefusalDoesNotFallThrough(t *testing.T) {
	server, _ := withAuthenticator(t, nil)
	bearer := sessionFor(t, server, adminID(t, server), "admin")
	cases := []struct {
		name, credential, bearer string
		want                     int
	}{
		{"accepted", "good", "", http.StatusOK},
		{"refused beside a valid bearer", "bad", bearer, http.StatusUnauthorized},
		{"not mine, bearer", "", bearer, http.StatusOK},
		{"not mine, nothing", "", "", http.StatusUnauthorized},
	}
	for _, c := range cases {
		if got := forestWith(t, server, c.credential, c.bearer); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

func principalCall(t *testing.T, server *Server, headers map[string]string) ApplicationResponse {
	t.Helper()
	return server.ApplicationCall(ApplicationRequest{Method: "GET", Target: "/principal", Headers: headers})
}

// GET /principal answers an authenticator's projection, and the engine's own projection otherwise.
func TestPrincipalAnswersTheAuthenticatorsProjection(t *testing.T) {
	server, _ := withAuthenticator(t, map[string]any{"id": "external-principal", "kind": "service"})
	response := principalCall(t, server, map[string]string{testCredentialHeader: "good"})
	var projected map[string]any
	if response.Status != 200 || json.Unmarshal(response.Body, &projected) != nil || projected["kind"] != "service" || projected["id"] != "external-principal" {
		t.Fatalf("projection answered %d %s", response.Status, response.Body)
	}
	bearer := sessionFor(t, server, adminID(t, server), "admin")
	response = principalCall(t, server, map[string]string{"Authorization": "Bearer " + bearer})
	var engine map[string]any
	if response.Status != 200 || json.Unmarshal(response.Body, &engine) != nil || engine["username"] != "admin" || engine["admin"] != true {
		t.Fatalf("engine projection answered %d %s", response.Status, response.Body)
	}
	if response := principalCall(t, server, map[string]string{testCredentialHeader: "malformed"}); response.Status != 401 {
		t.Fatalf("malformed headers answered %d", response.Status)
	}
}

// Each configuration part goes to the extension that declared it; an undeclared part is refused,
// a null one included, and an extension's refusal of its part is the configuration's.
func TestUndeclaredConfigurationPartsAreRefused(t *testing.T) {
	server, authenticator := withAuthenticator(t, nil)
	for name, parts := range map[string]map[string]json.RawMessage{
		"undeclared":      {"admission": json.RawMessage(`{"keyId":"k"}`)},
		"undeclared null": {"activation": json.RawMessage(`null`)},
		"owner refuses":   {"header": json.RawMessage(`"refuse"`)},
	} {
		if err := server.ConfigureParts(parts); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := server.ConfigureParts(map[string]json.RawMessage{"admission": json.RawMessage(`{}`)}); !errors.Is(err, ErrUndeclaredPart) {
		t.Fatalf("an undeclared part answered %v", err)
	}
	if err := server.ConfigureParts(map[string]json.RawMessage{"header": json.RawMessage(`{"a":1}`)}); err != nil {
		t.Fatal(err)
	}
	if string(authenticator.configured["header"]) != `{"a":1}` {
		t.Fatalf("the declared part reached its owner as %q", authenticator.configured["header"])
	}
	bare, _ := newStockServer(t)
	if err := bare.ConfigureParts(map[string]json.RawMessage{"admission": json.RawMessage(`{}`)}); !errors.Is(err, ErrUndeclaredPart) {
		t.Fatalf("a store with no extensions accepted a part: %v", err)
	}
	if err := bare.ConfigureParts(nil); err != nil {
		t.Fatalf("no parts at all was refused: %v", err)
	}
}

func withWhoAmIRoute(t *testing.T) (*Server, *atomic.Int64) {
	t.Helper()
	server, _ := newStockServer(t)
	calls := &atomic.Int64{}
	handler := func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		principal, ok := extension.PrincipalFrom(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":             ok,
			"user_id":        principal.UserID,
			"has_projection": principal.Projection != nil,
		})
	}
	route := extension.Route{Method: "GET", Pattern: "/ext/whoami", Handler: handler}
	if err := withRoutes(t, server, route); err != nil {
		t.Fatal(err)
	}
	return server, calls
}

func assertGuardedWhoAmI(t *testing.T, server *Server, token, wantUserID string) {
	t.Helper()
	req := httptest.NewRequest("GET", "/ext/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	httpReply := serve(t, server, req)
	if httpReply.Code != http.StatusOK {
		t.Fatalf("HTTP /ext/whoami status = %d: %s", httpReply.Code, httpReply.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(httpReply.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["ok"] != true || got["user_id"] != wantUserID || got["has_projection"] != false {
		t.Fatalf("HTTP /ext/whoami principal = %#v, want user %q with nil projection", got, wantUserID)
	}
	appReply := routeCall(t, server, token, "GET", "/ext/whoami", nil, http.StatusOK)
	if appReply["ok"] != true || appReply["user_id"] != wantUserID || appReply["has_projection"] != false {
		t.Fatalf("ApplicationCall /ext/whoami principal = %#v, want user %q with nil projection", appReply, wantUserID)
	}
}

func assertGuardedRefused(t *testing.T, server *Server, label, token string, calls *atomic.Int64) {
	t.Helper()
	before := calls.Load()
	req := httptest.NewRequest("GET", "/ext/whoami", nil)
	headers := map[string]string{}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		headers["Authorization"] = "Bearer " + token
	}
	if code := serve(t, server, req).Code; code != http.StatusUnauthorized {
		t.Fatalf("%s HTTP /ext/whoami answered %d, want 401", label, code)
	}
	if app := server.ApplicationCall(ApplicationRequest{Method: "GET", Target: "/ext/whoami", Headers: headers}); app.Status != http.StatusUnauthorized {
		t.Fatalf("%s ApplicationCall /ext/whoami answered %d, want 401", label, app.Status)
	}
	if calls.Load() != before {
		t.Fatalf("%s reached guarded handler (%d -> %d)", label, before, calls.Load())
	}
}

// Native browser (ms_) and native bearer sessions populate extension.PrincipalFrom on guarded
// routes across HTTP and ApplicationCall while keeping GET /principal on the engine projection.
func TestNativeSessionsPopulatePrincipalOnGuardedRoutes(t *testing.T) {
	server, _ := withWhoAmIRoute(t)
	alice := addLoginUser(t, server, "alice", nil)
	loginReply := applicationCall(t, server, "POST", "/session", passwordBody(alice))
	if loginReply.Status != http.StatusOK {
		t.Fatalf("POST /session answered %d %s", loginReply.Status, loginReply.Body)
	}
	browserToken := decodeApplication(t, loginReply)["token"].(string)
	bearerToken := sessionFor(t, server, alice.ID, alice.Username)

	assertGuardedWhoAmI(t, server, browserToken, alice.ID)
	assertGuardedWhoAmI(t, server, bearerToken, alice.ID)

	for kind, token := range map[string]string{"browser": browserToken, "bearer": bearerToken} {
		projected := routeCall(t, server, token, "GET", "/principal", nil, http.StatusOK)
		if projected["id"] != alice.ID || projected["username"] != "alice" || projected["admin"] != false {
			t.Fatalf("%s GET /principal = %#v", kind, projected)
		}
	}
}

func TestGuardedExtensionRouteRefusesUnauthenticatedAndRevokedTokens(t *testing.T) {
	server, calls := withWhoAmIRoute(t)
	alice := addLoginUser(t, server, "alice", nil)

	assertGuardedRefused(t, server, "missing token", "", calls)
	assertGuardedRefused(t, server, "malformed jwt", "not-a-jwt", calls)
	assertGuardedRefused(t, server, "unknown ms_ token", "ms_0000000000000000000000000000000000000000000000000000000000000000", calls)

	expiredToken, _, err := server.mintApplicationSession(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.changeForest(func() error {
		key := server.sessionKeyFromBearer(expiredToken)
		held := server.forest.ApplicationSessions[key]
		held.ExpiresAt = 1
		server.forest.ApplicationSessions[key] = held
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertGuardedRefused(t, server, "expired ms_ token", expiredToken, calls)

	revokedToken, _, err := server.mintApplicationSession(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	routeCall(t, server, revokedToken, "DELETE", "/session", nil, http.StatusOK)
	assertGuardedRefused(t, server, "signed-out ms_ token", revokedToken, calls)

	bearerToken := sessionFor(t, server, alice.ID, alice.Username)
	if err := server.changeForest(func() error {
		for index := range server.forest.Users {
			if server.forest.Users[index].ID == alice.ID {
				server.forest.Users[index].CredentialEpoch++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertGuardedRefused(t, server, "retired bearer token", bearerToken, calls)
}
