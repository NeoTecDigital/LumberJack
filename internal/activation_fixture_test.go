// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// A labeled private-authority DOUBLE, not real Supabase/session/grant evidence.
type activationAuthorityDouble struct {
	mu       sync.Mutex
	consumed map[string]bool
	calls    []activationCheck
	mode     string
	mutate   func(*activationActor)
}

func activationFixtureConfig(endpoint string) ActivationConfig {
	return ActivationConfig{VerifierEndpoint: endpoint + "/activation/verify", ChannelToken: "synthetic-private-channel-32-byte-fixture",
		Audience: "synthetic-native-audience", Issuer: "synthetic-authority-issuer", TimeoutMs: 1000,
		MaxProofBytes: 128, MaxBodyBytes: 1024, MaxResponseBytes: 4096, MaxLifetimeSeconds: 60, SyntheticLoopbackOnly: true}
}

func activationDouble(t *testing.T) (*Server, *activationAuthorityDouble, *httptest.Server) {
	t.Helper()
	authority := &activationAuthorityDouble{consumed: map[string]bool{}}
	callback := httptest.NewServer(http.HandlerFunc(authority.serve))
	t.Cleanup(callback.Close)
	server := &Server{}
	if err := server.ConfigureActivation(activationFixtureConfig(callback.URL)); err != nil {
		t.Fatal(err)
	}
	return server, authority, callback
}

func (a *activationAuthorityDouble) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.Path != "/activation/verify" || r.Header.Get("Authorization") != "Bearer synthetic-private-channel-32-byte-fixture" {
		activationWriteFailure(w, activationFailure{"handoff_unavailable", 503})
		return
	}
	var request activationCheck
	if json.NewDecoder(r.Body).Decode(&request) != nil {
		activationWriteFailure(w, activationFailure{"invalid_request", 422})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, request)
	if !a.admit(request) {
		activationWriteFailure(w, activationFailure{"access_denied", 403})
		return
	}
	if a.mode != "" {
		a.refuse(w)
		return
	}
	actor := activationFixtureActor()
	if a.mutate != nil {
		a.mutate(&actor)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(actor)
}

func (a *activationAuthorityDouble) admit(request activationCheck) bool {
	if request.Proof != "synthetic-proof-P-A" || request.Method != "GET" || request.Audience != "synthetic-native-audience" || request.BodySHA256 != activationEmptyDigest {
		return false
	}
	if request.Phase == "preflight" {
		return request.Target == "/principal"
	}
	if request.Phase != "execute" || request.Target != "/activation/probe" || a.consumed[request.Proof] {
		return false
	}
	a.consumed[request.Proof] = true
	return true
}

func (a *activationAuthorityDouble) refuse(w http.ResponseWriter) {
	status := map[string]int{"authority_unavailable": 503, "access_revoked": 403, "session_revoked": 401, "session_expired": 401}
	if a.mode == "redirect" {
		w.Header().Set("Location", "https://external.invalid/refused")
		w.WriteHeader(302)
		return
	}
	if a.mode == "timeout" {
		time.Sleep(30 * time.Millisecond)
		return
	}
	activationWriteFailure(w, activationFailure{a.mode, status[a.mode]})
}

func activationFixtureActor() activationActor {
	actor := activationActor{PrincipalID: "synthetic-principal-P", Kind: "human", SessionID: "synthetic-private-session",
		Scope: activationScope{AccountID: "synthetic-account-A", Product: "manifest"}, GrantRevision: "synthetic-grant-1",
		ResourceRevision: "synthetic-resource-1", ExpiresAt: float64(time.Now().Unix()) + 30, Method: "GET", Target: "/activation/probe",
		BodySHA256: activationEmptyDigest, Audience: "synthetic-native-audience", Issuer: "synthetic-authority-issuer", Action: "identity.read", Fields: []string{"principalId", "kind"}}
	actor.Resource.Kind, actor.Resource.ResourceID = "principal", actor.PrincipalID
	return actor
}

func activationCall(server *Server, target string) ApplicationResponse {
	return server.ApplicationCall(ApplicationRequest{Method: "GET", Target: target,
		Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A"}})
}
