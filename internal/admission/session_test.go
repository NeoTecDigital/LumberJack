// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package admission

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

const (
	sessionIssuer   = "activity-personal:installation"
	sessionAudience = "momentum-personal:installation"
	sessionNow      = int64(1000)
	sessionProfile  = `{"email":"person@example.test","username":"person"}`
)

func sessionClaims(principal string) Claims {
	digest := sha256.Sum256([]byte(sessionProfile))
	return Claims{1, sessionIssuer, sessionAudience, principal, "source-session", Scope{"personal-account", SessionProduct, ""},
		"sha256:grant", "personal-session/0.1", principal, SessionOperation, "command-1", hex.EncodeToString(digest[:]), sessionNow + 45, 1}
}

func sessionVerifier(t *testing.T, lifetime int64) (*Verifier, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	verifier, err := New(map[string]ed25519.PublicKey{"k": key.Public().(ed25519.PublicKey)}, sessionIssuer, sessionAudience, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, key
}

func TestVerifySessionAcceptsTheSignedAdmission(t *testing.T) {
	verifier, key := sessionVerifier(t, 60)
	claims := sessionClaims("person")
	got, err := verifier.VerifySession(signed(t, claims, key), []byte(sessionProfile), sessionNow)
	if err != nil {
		t.Fatal(err)
	}
	if got != claims {
		t.Fatalf("claims changed on the way through: %+v", got)
	}
}

func TestVerifySessionRefusesEveryOtherClaim(t *testing.T) {
	verifier, key := sessionVerifier(t, 60)
	changes := map[string]func(*Claims){
		"issuer":      func(c *Claims) { c.Issuer = "other" },
		"audience":    func(c *Claims) { c.Audience = "other" },
		"expired":     func(c *Claims) { c.ExpiresAt = sessionNow },
		"over-long":   func(c *Claims) { c.ExpiresAt = sessionNow + 61 },
		"operation":   func(c *Claims) { c.Operation = "other" },
		"product":     func(c *Claims) { c.Scope.Product = "manifest" },
		"workspace":   func(c *Claims) { c.Scope.WorkspaceID = "workspace" },
		"resource":    func(c *Claims) { c.ResourceID = "other" },
		"body":        func(c *Claims) { c.BodySHA256 = hex.EncodeToString(make([]byte, 32)) },
		"version":     func(c *Claims) { c.Version = 2 },
		"no-barrier":  func(c *Claims) { c.BarrierVersion = 0 },
		"bad-command": func(c *Claims) { c.CommandID = "not an atom" },
	}
	for name, change := range changes {
		claims := sessionClaims("person")
		change(&claims)
		if _, err := verifier.VerifySession(signed(t, claims, key), []byte(sessionProfile), sessionNow); err != ErrDenied {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestVerifySessionHoldsItsOwnLifetimeOverTheVerifiers(t *testing.T) {
	verifier, key := sessionVerifier(t, 300)
	claims := sessionClaims("person")
	claims.ExpiresAt = sessionNow + 61
	if _, err := verifier.VerifySession(signed(t, claims, key), []byte(sessionProfile), sessionNow); err != ErrDenied {
		t.Fatalf("a verifier allowing 300 s admitted a session past 60 s: %v", err)
	}
	claims.ExpiresAt = sessionNow + 60
	if _, err := verifier.VerifySession(signed(t, claims, key), []byte(sessionProfile), sessionNow); err != nil {
		t.Fatalf("exactly 60 s must pass: %v", err)
	}
}

func TestVerifySessionRefusesAForgedEnvelope(t *testing.T) {
	verifier, key := sessionVerifier(t, 60)
	raw := signed(t, sessionClaims("person"), key)
	stranger := ed25519.NewKeyFromSeed(append(make([]byte, 31), 1))
	if _, err := verifier.VerifySession(signed(t, sessionClaims("person"), stranger), []byte(sessionProfile), sessionNow); err != ErrDenied {
		t.Fatalf("another key's signature accepted: %v", err)
	}
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.KeyID = "unknown"
	unknown, _ := json.Marshal(envelope)
	if _, err := verifier.VerifySession(unknown, []byte(sessionProfile), sessionNow); err != ErrDenied {
		t.Fatalf("an unknown key accepted: %v", err)
	}
	if _, err := verifier.VerifySession(append([]byte(`{"keyId":"evil",`), raw[1:]...), []byte(sessionProfile), sessionNow); err != ErrDenied {
		t.Fatalf("a duplicate key accepted: %v", err)
	}
	spaced := base64.RawURLEncoding.EncodeToString(append([]byte(" "), []byte(`{}`)...))
	envelope.KeyID, envelope.Payload = "k", spaced
	padded, _ := json.Marshal(envelope)
	if _, err := verifier.VerifySession(padded, []byte(sessionProfile), sessionNow); err != ErrDenied {
		t.Fatalf("a non-canonical payload accepted: %v", err)
	}
}

func TestVerifySessionBindsTheExactProfileBytes(t *testing.T) {
	verifier, key := sessionVerifier(t, 60)
	raw := signed(t, sessionClaims("person"), key)
	for name, profile := range map[string]string{
		"another name":  `{"email":"person@example.test","username":"mallory"}`,
		"another email": `{"email":"mallory@example.test","username":"person"}`,
		"whitespace":    `{"email": "person@example.test","username":"person"}`,
		"reordered":     `{"username":"person","email":"person@example.test"}`,
		"empty":         ``,
	} {
		if _, err := verifier.VerifySession(raw, []byte(profile), sessionNow); err != ErrDenied {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

// The vector Activity's Python signer must reproduce byte for byte: the profile and its canonical
// form, the claims and theirs, the signature, the admission. backend/tests reads this same file.
func TestVerifySessionAcceptsTheSharedVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/session_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Seed             string `json:"seed"`
		KeyID            string `json:"keyId"`
		Public           string `json:"public"`
		Issuer           string `json:"issuer"`
		Audience         string `json:"audience"`
		Canonical        string `json:"canonical"`
		Signature        string `json:"signature"`
		Now              int64  `json:"now"`
		Claims           Claims `json:"claims"`
		ProfileCanonical string `json:"profileCanonical"`
		Admission        string `json:"admission"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(vector.Seed)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	public := key.Public().(ed25519.PublicKey)
	if base64.RawURLEncoding.EncodeToString(public) != vector.Public {
		t.Fatalf("the vector's public key does not belong to its seed")
	}
	if got := base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(vector.Canonical))); got != vector.Signature {
		t.Fatalf("the vector's signature does not belong to its canonical form: %s", got)
	}
	verifier, err := New(map[string]ed25519.PublicKey{vector.KeyID: public}, vector.Issuer, vector.Audience, MaxSessionLifetime)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Envelope json.RawMessage `json:"envelope"`
		Profile  json.RawMessage `json:"profile"`
	}
	if err := json.Unmarshal([]byte(vector.Admission), &wire); err != nil {
		t.Fatal(err)
	}
	if string(wire.Profile) != vector.ProfileCanonical {
		t.Fatalf("the admission does not carry the canonical profile bytes: %s", wire.Profile)
	}
	got, err := verifier.VerifySession(wire.Envelope, wire.Profile, vector.Now)
	if err != nil {
		t.Fatalf("the shared vector was refused: %v", err)
	}
	if got != vector.Claims {
		t.Fatalf("claims differ from the vector's: %+v", got)
	}
}
