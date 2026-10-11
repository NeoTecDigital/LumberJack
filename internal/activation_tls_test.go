// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestActivationVerifiedTLSAndChannelIsolation(t *testing.T) {
	authority := &activationAuthorityDouble{consumed: map[string]bool{}}
	callback := httptest.NewUnstartedServer(http.HandlerFunc(authority.serve))
	callback.Config.ErrorLog = log.New(io.Discard, "", 0)
	callback.StartTLS()
	defer callback.Close()
	config := activationFixtureConfig(callback.URL)
	config.SyntheticLoopbackOnly = false
	config.ServerName = "example.com"
	config.TrustedCAPem = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: callback.Certificate().Raw}))
	activationTLSResult(t, config, 200)
	config.ServerName = "wrong.example.invalid"
	activationTLSResult(t, config, 503)
	config.ServerName = "example.com"
	config.ChannelToken = "wrong-synthetic-channel-32-byte-fixture"
	activationTLSResult(t, config, 503)
}

func activationTLSResult(t *testing.T, config ActivationConfig, expected int) {
	t.Helper()
	server := &Server{}
	if err := server.ConfigureActivation(config); err != nil {
		t.Fatal(err)
	}
	result := activationCall(server, "/principal")
	if result.Status != expected {
		t.Fatalf("TLS/channel status=%d expected=%d", result.Status, expected)
	}
}
