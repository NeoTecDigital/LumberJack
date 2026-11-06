// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// These are configuration-only tests, not human authentication evidence.
func localHumanTrustConfig(endpoint string) ActivationConfig {
	config := activationFixtureConfig("http://127.0.0.1:18745")
	config.VerifierEndpoint = endpoint
	config.SyntheticLoopbackOnly = false
	config.LocalHumanPreview = true
	return config
}

func TestLocalHumanTrustAcceptsExplicitLoopbackWithoutTLS(t *testing.T) {
	for _, endpoint := range []string{"http://127.0.0.1:18745/activation/verify", "http://[::1]:18745/activation/verify"} {
		config := localHumanTrustConfig(endpoint)
		verifier, err := newActivationVerifier(config)
		if err != nil {
			t.Fatal(err)
		}
		transport := verifier.client.Transport.(*http.Transport)
		if transport.TLSClientConfig != nil || transport.Proxy != nil || !transport.DisableKeepAlives {
			t.Fatal("local transport has implicit TLS/proxy/connection reuse")
		}
		if _, err = newDomainVerifier(config); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLocalHumanTrustUnsafeEndpointsFailClosed(t *testing.T) {
	endpoints := []string{"http://localhost:18745/activation/verify", "http://192.0.2.1:18745/activation/verify",
		"https://127.0.0.1:18745/activation/verify", "http://127.0.0.1/activation/verify",
		"http://127.0.0.1:80/activation/verify", "http://127.0.0.1:65536/activation/verify",
		"http://user@127.0.0.1:18745/activation/verify", "http://[::1%25eth0]:18745/activation/verify",
		"http://127.0.0.1:18745/activation/verify?", "http://127.0.0.1:18745/activation/verify?redirect=x",
		"http://127.0.0.1:18745/activation/verify#external", "http://127.0.0.1:18745/activation/%76erify"}
	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			assertLocalHumanTrustDenied(t, localHumanTrustConfig(endpoint))
		})
	}
}

func TestLocalHumanTrustModesAreExclusiveAndDefaultIsTLS(t *testing.T) {
	config := localHumanTrustConfig("http://127.0.0.1:18745/activation/verify")
	config.SyntheticLoopbackOnly = true
	assertLocalHumanTrustDenied(t, config)
	if _, err := activationTLS(config); err == nil {
		t.Fatal("conflicting TLS bypass modes accepted")
	}
	config.SyntheticLoopbackOnly = false
	config.LocalHumanPreview = false
	assertLocalHumanTrustDenied(t, config)
	config.VerifierEndpoint = "https://127.0.0.1:18745/activation/verify"
	assertLocalHumanTrustDenied(t, config)
}

func assertLocalHumanTrustDenied(t *testing.T, config ActivationConfig) {
	t.Helper()
	if ValidateActivationConfig(config) == nil {
		t.Fatal("invalid Activation trust accepted")
	}
	if _, err := newDomainVerifier(config); err == nil {
		t.Fatal("invalid domain trust accepted")
	}
}

func TestLocalHumanTrustRequiresExistingFiniteBounds(t *testing.T) {
	mutations := map[string]func(*ActivationConfig){
		"zero timeout":        func(c *ActivationConfig) { c.TimeoutMs = 0 },
		"timeout ceiling":     func(c *ActivationConfig) { c.TimeoutMs = 60001 },
		"proof minimum":       func(c *ActivationConfig) { c.MaxProofBytes = 42 },
		"proof ceiling":       func(c *ActivationConfig) { c.MaxProofBytes = (1 << 20) + 1 },
		"zero body":           func(c *ActivationConfig) { c.MaxBodyBytes = 0 },
		"body ceiling":        func(c *ActivationConfig) { c.MaxBodyBytes = applicationLimit + 1 },
		"zero response":       func(c *ActivationConfig) { c.MaxResponseBytes = 0 },
		"response ceiling":    func(c *ActivationConfig) { c.MaxResponseBytes = applicationLimit + 1 },
		"zero lifetime":       func(c *ActivationConfig) { c.MaxLifetimeSeconds = 0 },
		"lifetime ceiling":    func(c *ActivationConfig) { c.MaxLifetimeSeconds = 3601 },
		"whitespace issuer":   func(c *ActivationConfig) { c.Issuer = " \t" },
		"whitespace audience": func(c *ActivationConfig) { c.Audience = " \t" },
		"short channel":       func(c *ActivationConfig) { c.ChannelToken = strings.Repeat("x", 31) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			config := localHumanTrustConfig("http://127.0.0.1:18745/activation/verify")
			mutate(&config)
			assertLocalHumanTrustDenied(t, config)
		})
	}
}

func TestLocalHumanTrustStrictJSONOptionalBoolean(t *testing.T) {
	config := localHumanTrustConfig("http://127.0.0.1:18745/activation/verify")
	body, _ := json.Marshal(config)
	decoded, err := DecodeActivationConfig(body)
	if err != nil || !decoded.LocalHumanPreview || decoded.SyntheticLoopbackOnly {
		t.Fatal("explicit separate local human mode refused")
	}
	for _, replacement := range []string{`"localHumanPreview":null`, `"localHumanPreview":"true"`,
		`"localHumanPreview":1`, `"localHumanPreview":true,"localHumanPreview":false`, `"unexpectedMode":true`} {
		invalid := bytes.Replace(body, []byte(`"localHumanPreview":true`), []byte(replacement), 1)
		if _, err := DecodeActivationConfig(invalid); err == nil {
			t.Fatal("malformed or unknown local mode accepted")
		}
	}
	legacy := activationFixtureConfig("http://127.0.0.1:18745")
	body, _ = json.Marshal(legacy)
	decoded, err = DecodeActivationConfig(body)
	if err != nil || decoded.LocalHumanPreview || !decoded.SyntheticLoopbackOnly {
		t.Fatal("legacy synthetic mode changed")
	}
}

func TestLocalHumanDomainTrustStrictJSONAndConfiguredPath(t *testing.T) {
	config := localHumanTrustConfig("http://127.0.0.1:18745/private/domain/verify")
	if _, err := newDomainVerifier(config); err != nil {
		t.Fatal("explicit domain callback path refused")
	}
	body, _ := json.Marshal(config)
	var decoded ActivationConfig
	if err := DecodeDomainJSON(body, &decoded); err != nil || !decoded.LocalHumanPreview {
		t.Fatal("domain trust JSON omitted explicit local human mode")
	}
	for _, replacement := range []string{`"localHumanPreview":"true"`, `"unexpectedMode":true`,
		`"localHumanPreview":true,"localHumanPreview":false`} {
		invalid := bytes.Replace(body, []byte(`"localHumanPreview":true`), []byte(replacement), 1)
		if DecodeDomainJSON(invalid, &decoded) == nil {
			t.Fatal("malformed domain trust JSON accepted")
		}
	}
}
