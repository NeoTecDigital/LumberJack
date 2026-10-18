// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import "testing"

func TestActivationRequiresExplicitConfiguredApplicationAndOneShotTrust(t *testing.T) {
	isolatedApplicationSecurity(t)
	handle, err := Open(embeddedConfig(t), "synthetic-native-owner")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	config := ActivationConfig{VerifierEndpoint: "http://127.0.0.1:18745/activation/verify",
		ChannelToken: "synthetic-private-channel-32-byte-fixture", Audience: "synthetic-native-audience", Issuer: "synthetic-authority",
		TimeoutMs: 1000, MaxProofBytes: 128, MaxBodyBytes: 1024, MaxResponseBytes: 4096, MaxLifetimeSeconds: 60,
		SyntheticLoopbackOnly: true}
	if handle.ConfigureActivation(config) == nil {
		t.Fatal("unconfigured application accepted activation")
	}
	if err := handle.ConfigureApplication("synthetic-owner", applicationCredential(), applicationCredential()); err != nil {
		t.Fatal(err)
	}
	result, err := handle.ApplicationCall(ApplicationRequest{Method: "GET", Target: "/principal",
		Headers: map[string]string{"Authorization": "Activation synthetic-proof"}})
	if err != nil || result.Status != 503 {
		t.Fatal("absent activation did not remain disabled")
	}
	invalid := config
	invalid.SyntheticLoopbackOnly = false
	if handle.ConfigureActivation(invalid) == nil {
		t.Fatal("invalid trust accepted")
	}
	if err := handle.ConfigureActivation(config); err != nil {
		t.Fatal(err)
	}
	if handle.ConfigureActivation(config) == nil {
		t.Fatal("activation trust replaced")
	}
	result, err = handle.ApplicationCall(ApplicationRequest{Method: "GET", Target: "/workspace",
		Headers: map[string]string{"Authorization": "Activation synthetic-proof"}})
	if err != nil || result.Status != 403 {
		t.Fatal("external identity crossed into native business authority")
	}
	_ = handle.Close()
	if handle.ConfigureActivation(config) == nil {
		t.Fatal("closed handle accepted activation")
	}
}
