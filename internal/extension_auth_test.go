// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
