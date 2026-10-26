// Written by Richard Christopher, Copyright 2026 Mindfull
// Package admission provides no ambient keys, authority fallback or runtime routes.
package admission

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

var ErrDenied = errors.New("admission_denied")
var atom = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,256}$`)
var hash = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Scope struct {
	AccountID   string `json:"accountId"`
	Product     string `json:"product"`
	WorkspaceID string `json:"workspaceId,omitempty"`
}

type Claims struct {
	Version          int    `json:"version"`
	Issuer           string `json:"issuer"`
	Audience         string `json:"audience"`
	PrincipalID      string `json:"principalId"`
	SessionID        string `json:"sessionId"`
	Scope            Scope  `json:"scope"`
	GrantRevision    string `json:"grantRevision"`
	ResourceRevision string `json:"resourceRevision"`
	ResourceID       string `json:"resourceId"`
	Operation        string `json:"operation"`
	CommandID        string `json:"commandId"`
	BodySHA256       string `json:"bodySha256"`
	ExpiresAt        int64  `json:"expiresAt"`
	BarrierVersion   uint64 `json:"barrierVersion"`
}

type Envelope struct {
	KeyID     string `json:"keyId"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type Barrier struct {
	Version   uint64
	Confirmed bool
}

// ReadBarrier must read durable state INSIDE the same serialized commit operation.
// A preflight database/network read is not a valid implementation of this port.
type ReadBarrier func(Scope, string, string) (Barrier, error)

type Verifier struct {
	keys             map[string]ed25519.PublicKey
	issuer, audience string
	lifetime         int64
}

func New(keys map[string]ed25519.PublicKey, issuer, audience string, maxLifetime int64) (*Verifier, error) {
	if len(keys) == 0 || !atom.MatchString(issuer) || !atom.MatchString(audience) || maxLifetime <= 0 || maxLifetime > 300 {
		return nil, ErrDenied
	}
	copyKeys := make(map[string]ed25519.PublicKey)
	for id, key := range keys {
		if !atom.MatchString(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrDenied
		}
		copyKeys[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &Verifier{copyKeys, issuer, audience, maxLifetime}, nil
}

// Verify binds every field except expiry to a trusted command/ACL expectation.
// Calling this outside the replicated FSM commit boundary DOES NOT fence writes.
func (v *Verifier) Verify(raw []byte, expected Claims, payload []byte, now int64, read ReadBarrier) (Claims, error) {
	var envelope Envelope
	if len(raw) > 8192 || !uniqueObject(raw) || decode(raw, &envelope) != nil || !atom.MatchString(envelope.KeyID) {
		return Claims{}, ErrDenied
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || len(body) > 4096 {
		return Claims{}, ErrDenied
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(v.keys[envelope.KeyID]) != ed25519.PublicKeySize || !ed25519.Verify(v.keys[envelope.KeyID], body, signature) {
		return Claims{}, ErrDenied
	}
	var claims Claims
	if decode(body, &claims) != nil || !valid(claims) || !canonical(body) {
		return Claims{}, ErrDenied
	}
	if claims.Issuer != v.issuer || claims.Audience != v.audience || claims.ExpiresAt <= now || claims.ExpiresAt-now > v.lifetime {
		return Claims{}, ErrDenied
	}
	expected.ExpiresAt = claims.ExpiresAt
	if claims != expected {
		return Claims{}, ErrDenied
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != claims.BodySHA256 || read == nil {
		return Claims{}, ErrDenied
	}
	barrier, err := read(claims.Scope, claims.PrincipalID, claims.SessionID)
	if err != nil || !barrier.Confirmed || barrier.Version != claims.BarrierVersion {
		return Claims{}, ErrDenied
	}
	return claims, nil
}

func valid(c Claims) bool {
	fields := []string{c.Issuer, c.Audience, c.PrincipalID, c.SessionID, c.GrantRevision, c.ResourceRevision, c.ResourceID, c.Operation, c.CommandID, c.Scope.AccountID}
	for _, field := range fields {
		if !atom.MatchString(field) {
			return false
		}
	}
	if c.Scope.WorkspaceID != "" && !atom.MatchString(c.Scope.WorkspaceID) {
		return false
	}
	return c.Version == 1 && (c.Scope.Product == "momentum" || c.Scope.Product == "manifest") && hash.MatchString(c.BodySHA256) && c.BarrierVersion > 0 && c.BarrierVersion <= 9007199254740991 && c.ExpiresAt > 0 && c.ExpiresAt <= 9007199254740991
}

func decode(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrDenied
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrDenied
	}
	return nil
}

func canonical(raw []byte) bool {
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil || len(value) != 14 {
		return false
	}
	scope, ok := value["scope"].(map[string]any)
	if !ok || len(scope) < 2 || len(scope) > 3 {
		return false
	}
	if workspace, exists := scope["workspaceId"]; exists && workspace == "" {
		return false
	}
	encoded, err := json.Marshal(value)
	return err == nil && bytes.Equal(encoded, raw)
}

// The envelope contains only strings; token scanning rejects duplicate keys.
func uniqueObject(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return false
		}
		seen[name] = true
		value, err := decoder.Token()
		if _, ok := value.(string); err != nil || !ok {
			return false
		}
	}
	last, err := decoder.Token()
	return err == nil && last == json.Delim('}') && len(seen) == 3
}
