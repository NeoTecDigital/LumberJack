// Written by Richard Christopher, Copyright 2026 Mindfull
package admission

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func fixture(t *testing.T) (*Verifier, Claims, []byte, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	verifier, err := New(map[string]ed25519.PublicKey{"k": key.Public().(ed25519.PublicKey)}, "issuer", "aud", 60)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("opaque")
	digest := sha256.Sum256(payload)
	claims := Claims{1, "issuer", "aud", "p", "s", Scope{"a", "momentum", ""}, "g", "r", "resource", "write", "c", hex.EncodeToString(digest[:]), 120, 2}
	return verifier, claims, payload, key
}

func signed(t *testing.T, claims Claims, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, _ := json.Marshal(claims)
	var value map[string]any
	_ = json.Unmarshal(raw, &value)
	raw, _ = json.Marshal(value)
	envelope := Envelope{"k", base64.RawURLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))}
	result, _ := json.Marshal(envelope)
	return result
}

func TestStrictBindings(t *testing.T) {
	verifier, claims, payload, key := fixture(t)
	read := func(Scope, string, string) (Barrier, error) { return Barrier{2, true}, nil }
	raw := signed(t, claims, key)
	if _, err := verifier.Verify(raw, claims, payload, 100, read); err != nil {
		t.Fatal(err)
	}
	wrong := claims
	wrong.Scope.Product = "manifest"
	if _, err := verifier.Verify(raw, wrong, payload, 100, read); err == nil {
		t.Fatal("scope accepted")
	}
	wrong = claims
	wrong.SessionID = "other"
	if _, err := verifier.Verify(raw, wrong, payload, 100, read); err == nil {
		t.Fatal("session accepted")
	}
	if _, err := verifier.Verify(raw, claims, []byte("changed"), 100, read); err == nil {
		t.Fatal("payload accepted")
	}
	if _, err := verifier.Verify(raw, claims, payload, 120, read); err == nil {
		t.Fatal("expired accepted")
	}
}

func TestCommitBarrierAndTamper(t *testing.T) {
	verifier, claims, payload, key := fixture(t)
	raw := signed(t, claims, key)
	for _, barrier := range []Barrier{{2, false}, {3, true}, {1, true}} {
		read := func(Scope, string, string) (Barrier, error) { return barrier, nil }
		if _, err := verifier.Verify(raw, claims, payload, 100, read); err == nil {
			t.Fatal("barrier accepted")
		}
	}
	if _, err := verifier.Verify(raw, claims, payload, 100, nil); err == nil {
		t.Fatal("missing commit port")
	}
	var envelope Envelope
	_ = json.Unmarshal(raw, &envelope)
	envelope.KeyID = "unknown"
	raw, _ = json.Marshal(envelope)
	if _, err := verifier.Verify(raw, claims, payload, 100, nil); err == nil {
		t.Fatal("unknown key")
	}
}

func TestEverySignedBindingRefusesRetarget(t *testing.T) {
	verifier, claims, payload, key := fixture(t)
	raw := signed(t, claims, key)
	read := func(Scope, string, string) (Barrier, error) { return Barrier{2, true}, nil }
	changes := []func(*Claims){
		func(c *Claims) { c.PrincipalID = "other" },
		func(c *Claims) { c.Scope.AccountID = "other" },
		func(c *Claims) { c.Scope.WorkspaceID = "other" },
		func(c *Claims) { c.GrantRevision = "other" },
		func(c *Claims) { c.ResourceRevision = "other" },
		func(c *Claims) { c.ResourceID = "other" },
		func(c *Claims) { c.Operation = "other" },
		func(c *Claims) { c.CommandID = "other" },
		func(c *Claims) { c.BarrierVersion = 3 },
		func(c *Claims) { c.Issuer = "other" },
		func(c *Claims) { c.Audience = "other" },
	}
	for _, change := range changes {
		wrong := claims
		change(&wrong)
		if _, err := verifier.Verify(raw, wrong, payload, 100, read); err == nil {
			t.Fatal("retarget accepted")
		}
	}
}

func TestDuplicateEnvelopeAndBadSignature(t *testing.T) {
	verifier, claims, payload, key := fixture(t)
	raw := signed(t, claims, key)
	duplicate := append([]byte(`{"keyId":"evil",`), raw[1:]...)
	read := func(Scope, string, string) (Barrier, error) { return Barrier{2, true}, nil }
	if _, err := verifier.Verify(duplicate, claims, payload, 100, read); err == nil {
		t.Fatal("duplicate accepted")
	}
	var envelope Envelope
	_ = json.Unmarshal(raw, &envelope)
	envelope.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	raw, _ = json.Marshal(envelope)
	if _, err := verifier.Verify(raw, claims, payload, 100, read); err == nil {
		t.Fatal("signature accepted")
	}
}
