// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/NeoTecDigital/LumberJack/embedded"
	"github.com/NeoTecDigital/LumberJack/types"
)

// The `auth` JSON is the one way the keys reach the engine, so its reading is proven at this seam:
// a good admission part configures, a bad one fails the open, and no part at all stays as it was.
func TestApplicationConfigurationCarriesTheSessionAdmission(t *testing.T) {
	t.Setenv("MOMENTUM_REQUIRE_MFA", "true")
	key := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey))
	good := json.RawMessage(`{"keyId":"k","publicKey":"` + key + `","issuer":"i","audience":"a"}`)
	for name, part := range map[string]struct {
		admission json.RawMessage
		fails     bool
	}{
		"none":     {nil, false},
		"good":     {good, false},
		"null":     {json.RawMessage(`null`), true},
		"bad key":  {json.RawMessage(`{"keyId":"k","publicKey":"AAAA","issuer":"i","audience":"a"}`), true},
		"extra":    {json.RawMessage(`{"keyId":"k","publicKey":"` + key + `","issuer":"i","audience":"a","seed":"x"}`), true},
		"no field": {json.RawMessage(`{}`), true},
	} {
		handle, err := embedded.Open(embedded.Config{Process: types.ProcessInfo{Name: "ffi_admission", DatabasePath: t.TempDir()}}, "system")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err = configureApplication(handle, applicationConfiguration{Username: "operator", Password: "a-long-enough-password",
			Secret: "a-long-enough-signing-key-0123456789", Admission: part.admission})
		if (err != nil) != part.fails {
			t.Errorf("%s: configure answered %v", name, err)
		}
		if err := handle.Close(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
