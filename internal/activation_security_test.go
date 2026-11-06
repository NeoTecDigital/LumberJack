// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestActivationActorResponseBindingsFailClosed(t *testing.T) {
	cases := map[string]func(*activationActor){
		"issuer": func(a *activationActor) { a.Issuer = "other" }, "audience": func(a *activationActor) { a.Audience = "other" },
		"kind": func(a *activationActor) { a.Kind = "agent" }, "scope": func(a *activationActor) { a.Scope.Product = "momentum" },
		"expiry": func(a *activationActor) { a.ExpiresAt = float64(time.Now().Unix()) - 1 },
		"future": func(a *activationActor) { a.ExpiresAt = float64(time.Now().Unix()) + 999 },
		"method": func(a *activationActor) { a.Method = "POST" }, "target": func(a *activationActor) { a.Target = "/workspace" },
		"digest":   func(a *activationActor) { a.BodySHA256 = strings.Repeat("0", 64) },
		"resource": func(a *activationActor) { a.Resource.ResourceID = "submitted-actor" },
		"action":   func(a *activationActor) { a.Action = "admin" }, "fields": func(a *activationActor) { a.Fields = []string{"principalId", "kind", "password"} },
		"session": func(a *activationActor) { a.SessionID = "" }, "grant": func(a *activationActor) { a.GrantRevision = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) { activationBadActor(t, mutate) })
	}
}

func activationBadActor(t *testing.T, mutate func(*activationActor)) {
	server, authority, _ := activationDouble(t)
	authority.mutate = mutate
	result := activationCall(server, "/principal")
	if result.Status != 503 || strings.Contains(string(result.Body), "principalId") {
		t.Fatal("unbound authority response disclosed actor")
	}
}

func TestActivationPrivateChannelRedirectTimeoutAndBounds(t *testing.T) {
	server, authority, _ := activationDouble(t)
	authority.mode = "redirect"
	if activationCall(server, "/principal").Status != 503 {
		t.Fatal("callback redirect was followed/admitted")
	}
	authority.mode = "timeout"
	server.activation.Load().client.Timeout = time.Millisecond
	if activationCall(server, "/principal").Status != 503 {
		t.Fatal("callback timeout was admitted")
	}
}

func TestActivationResponseAndProofLimits(t *testing.T) {
	server, _, _ := activationDouble(t)
	verifier := server.activation.Load()
	verifier.config.MaxResponseBytes = 4
	if activationCall(server, "/principal").Status != 503 {
		t.Fatal("oversize response admitted")
	}
	verifier.config.MaxProofBytes = 4
	if activationCall(server, "/principal").Status != 401 {
		t.Fatal("oversize proof admitted")
	}
	verifier.config.MaxProofBytes = 128
	verifier.config.MaxBodyBytes = 1
	request := ApplicationRequest{Method: "GET", Target: "/activation/probe", Headers: map[string]string{"Authorization": "Activation synthetic-proof-P-A"}, Body: []byte("xx")}
	if server.ApplicationCall(request).Status != 422 {
		t.Fatal("oversize request body admitted")
	}
}

func TestActivationCanceledRequestCannotDiscloseActor(t *testing.T) {
	server, authority, _ := activationDouble(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("GET", "/principal", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Activation synthetic-proof-P-A")
	out := httptest.NewRecorder()
	called := false
	server.authMiddleware(func(http.ResponseWriter, *http.Request) { called = true })(out, req)
	if called || out.Code != 503 || len(authority.calls) != 0 {
		t.Fatal("canceled request disclosed identity or reached authority")
	}
}

func TestActivationExecutionProofOneUseUnderConcurrency(t *testing.T) {
	server, _, _ := activationDouble(t)
	var group sync.WaitGroup
	results := make(chan int, 8)
	for i := 0; i < 8; i++ {
		group.Add(1)
		go activationConcurrentCall(server, &group, results)
	}
	group.Wait()
	close(results)
	admitted := 0
	for status := range results {
		if status == 200 {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("one-use admitted %d executions", admitted)
	}
}

func activationConcurrentCall(server *Server, group *sync.WaitGroup, results chan<- int) {
	defer group.Done()
	results <- activationCall(server, "/activation/probe").Status
}

func TestActivationStrictJSONAndRequiredConfig(t *testing.T) {
	config := activationFixtureConfig("http://127.0.0.1:18745")
	body, _ := json.Marshal(config)
	if _, err := DecodeActivationConfig(body); err != nil {
		t.Fatal("complete explicit config refused")
	}
	var fields map[string]any
	_ = json.Unmarshal(body, &fields)
	delete(fields, "syntheticLoopbackOnly")
	missing, _ := json.Marshal(fields)
	if _, err := DecodeActivationConfig(missing); err == nil {
		t.Fatal("missing explicit mode accepted")
	}
	for _, invalid := range []string{`{"code":"access_denied","code":"handoff_unavailable"}`, `{"scope":{"accountId":"A","product":"manifest","workspaceId":null}}`, `{} {}`, `{"proof":null}`} {
		if strictActivationJSON([]byte(invalid), new(any)) == nil {
			t.Fatal("ambiguous/null/trailing JSON accepted")
		}
	}
	fields["syntheticLoopbackOnly"] = true
	fields["unexpected"] = true
	unknown, _ := json.Marshal(fields)
	if _, err := DecodeActivationConfig(unknown); err == nil {
		t.Fatal("unknown configuration accepted")
	}
}

func TestActivationConfigurationHasNoDNSHTTPProductionOrDefaultTrust(t *testing.T) {
	for _, endpoint := range []string{"https://external.invalid:443/activation/verify", "http://192.0.2.1:8081/activation/verify",
		"file:///activation/verify", "http://127.0.0.1:18745/activation/verify?redirect=external", "http://user@127.0.0.1:18745/activation/verify"} {
		config := activationFixtureConfig("http://127.0.0.1:18745")
		config.VerifierEndpoint = endpoint
		if ValidateActivationConfig(config) == nil {
			t.Fatal("unsafe verifier target accepted")
		}
	}
	config := activationFixtureConfig("http://127.0.0.1:18745")
	config.SyntheticLoopbackOnly = false
	if ValidateActivationConfig(config) == nil {
		t.Fatal("plaintext production channel accepted")
	}
	config.VerifierEndpoint = "https://127.0.0.1:18745/activation/verify"
	if ValidateActivationConfig(config) == nil {
		t.Fatal("implicit TLS trust accepted")
	}
}

func TestActivationTrustMinimumsRejectMalformedConfig(t *testing.T) {
	cases := map[string]func(*ActivationConfig){
		"31-byte channel":           func(c *ActivationConfig) { c.ChannelToken = strings.Repeat("x", 31) },
		"42-byte proof bound":       func(c *ActivationConfig) { c.MaxProofBytes = 42 },
		"whitespace issuer":         func(c *ActivationConfig) { c.Issuer = " \t\n" },
		"whitespace audience":       func(c *ActivationConfig) { c.Audience = "\u00a0\t" },
		"31-byte multibyte channel": func(c *ActivationConfig) { c.ChannelToken = strings.Repeat("é", 15) + "x" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) { activationMinimumRejected(t, mutate) })
	}
}

func activationMinimumRejected(t *testing.T, mutate func(*ActivationConfig)) {
	t.Helper()
	config := activationFixtureConfig("http://127.0.0.1:18745")
	mutate(&config)
	if ValidateActivationConfig(config) == nil {
		t.Fatal("malformed private trust minimum accepted")
	}
}

func TestActivationTrustMinimumsAcceptExactByteBoundaries(t *testing.T) {
	config := activationFixtureConfig("http://127.0.0.1:18745")
	config.MaxProofBytes = 43
	for _, channel := range []string{strings.Repeat("x", 32), strings.Repeat("é", 16)} {
		config.ChannelToken = channel
		if len(channel) != 32 || ValidateActivationConfig(config) != nil {
			t.Fatal("valid 32-byte channel and 43-byte proof bound refused")
		}
	}
}
