// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestActivationPreflightAndExecutionUseActualTypedActor(t *testing.T) {
	server, authority, _ := activationDouble(t)
	for i := 0; i < 2; i++ {
		result := activationCall(server, "/principal")
		if result.Status != 200 {
			t.Fatalf("preflight status %d", result.Status)
		}
		var body map[string]any
		_ = json.Unmarshal(result.Body, &body)
		if body["id"] != "synthetic-principal-P" || body["principalId"] != body["id"] {
			t.Fatal("preflight substituted actor")
		}
		assertActivationProjection(t, result)
	}
	if len(authority.consumed) != 0 {
		t.Fatal("preflight consumed execution")
	}
	result := activationCall(server, "/activation/probe")
	if result.Status != 200 {
		t.Fatalf("execution status %d", result.Status)
	}
	assertActivationProjection(t, result)
	if activationCall(server, "/activation/probe").Status != 403 {
		t.Fatal("execution replay was admitted")
	}
	if len(authority.calls) != 4 || authority.calls[0].Phase != "preflight" || authority.calls[2].Phase != "execute" {
		t.Fatal("request phases changed")
	}
}

func assertActivationProjection(t *testing.T, result ApplicationResponse) {
	t.Helper()
	for _, private := range []string{"synthetic-proof", "synthetic-private", "sessionId", "user_id", "admin", "username"} {
		if strings.Contains(string(result.Body), private) {
			t.Fatal("private/native identity escaped public projection")
		}
	}
	if result.Headers["Cache-Control"] != "no-store" {
		t.Fatal("sensitive context is cacheable")
	}
}

func TestActivationNeverInjectsLegacyUserID(t *testing.T) {
	server, _, _ := activationDouble(t)
	req := httptest.NewRequest("GET", "/principal", nil)
	req.Header.Set("Authorization", "Activation synthetic-proof-P-A")
	called := false
	server.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := userIDFrom(r); ok {
			t.Error("external actor became legacy native user")
		}
		if _, ok := r.Context().Value(activationContextKey{}).(activationActor); !ok {
			t.Error("typed external context missing")
		}
	})(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("typed external actor was not admitted")
	}
}

func TestActivationMixedAndUnknownRequestsRefuseBeforeAuthority(t *testing.T) {
	server, authority, _ := activationDouble(t)
	requests := []ApplicationRequest{
		{Method: "GET", Target: "/principal", Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A", "authorization": "Bearer native"}},
		{Method: "GET", Target: "/principal", Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A", "Cookie": "native-session"}},
		{Method: "GET", Target: "/principal", Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A", "Cookie": "", "cookie": "native-session"}},
		{Method: "GET", Target: "/principal", Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A", "Proxy-Authorization": "", "proxy-authorization": "Bearer native"}},
		{Method: "GET", Target: "/principal", Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A, Bearer native"}},
		{Method: "POST", Target: "/activation/probe", Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A"}},
		{Method: "GET", Target: "/activation/probe?accountId=other", Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A"}},
		{Method: "GET", Target: "/workspace", Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A"}},
		{Method: "POST", Target: "/login", Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A"}},
	}
	for _, request := range requests {
		result := server.ApplicationCall(request)
		if result.Status != 401 && result.Status != 403 {
			t.Fatalf("unexpected refusal status %d", result.Status)
		}
	}
	if len(authority.calls) != 0 {
		t.Fatal("mixed/unsupported request reached authority")
	}
}

func TestActivationBodyAndSubmittedScopeCannotRetargetProof(t *testing.T) {
	server, authority, _ := activationDouble(t)
	request := ApplicationRequest{Method: "GET", Target: "/activation/probe", Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A"}, Body: []byte(`{"accountId":"synthetic-account-B","principalId":"spoof"}`)}
	if server.ApplicationCall(request).Status != 403 {
		t.Fatal("body tamper was admitted")
	}
	if len(authority.consumed) != 0 {
		t.Fatal("unbound body consumed a valid execution")
	}
	request.Body = nil
	request.Headers["X-Actor"] = "submitted-admin"
	request.Headers["X-Account-ID"] = "synthetic-account-B"
	result := server.ApplicationCall(request)
	if result.Status != 200 || strings.Contains(string(result.Body), "submitted-admin") || strings.Contains(string(result.Body), "synthetic-account-B") {
		t.Fatal("submitted actor/scope replaced authority")
	}
}

func TestActivationCurrentAuthorityRecheckedAfterPreflight(t *testing.T) {
	for _, code := range []string{"access_revoked", "session_revoked", "session_expired", "authority_unavailable"} {
		t.Run(code, func(t *testing.T) { activationAuthorityRecheck(t, code) })
	}
}

func activationAuthorityRecheck(t *testing.T, code string) {
	server, authority, _ := activationDouble(t)
	if activationCall(server, "/principal").Status != 200 {
		t.Fatal("preflight failed")
	}
	authority.mode = code
	result := activationCall(server, "/activation/probe")
	if result.Status < 400 || strings.Contains(string(result.Body), "principalId") {
		t.Fatal("authority refusal disclosed context")
	}
	if !authority.consumed["synthetic-proof-P-A"] {
		t.Fatal("execution was not consumed before authority outcome")
	}
}

func TestActivationUnconfiguredNeverUsesLegacyIdentity(t *testing.T) {
	server := &Server{}
	if activationCall(server, "/principal").Status != 503 {
		t.Fatal("unconfigured external verifier fell back")
	}
}
