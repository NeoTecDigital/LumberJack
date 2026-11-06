// Written by Richard Christopher, Copyright 2026 Mindfull
// Package ciphertext validates opaque client ciphertext. It has no key or decrypt API.
package ciphertext

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
)

const MaxBytes = 16 * 1024 * 1024

var ErrInvalid = errors.New("invalid ciphertext envelope or context")

type Envelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"keyId"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}
type Context struct {
	Version     int    `json:"version"`
	AccountID   string `json:"accountId"`
	Product     string `json:"product"`
	WorkspaceID string `json:"workspaceId,omitempty"`
	ResourceID  string `json:"resourceId"`
	RecordID    string `json:"recordId"`
	Revision    uint64 `json:"revision"`
	KeyID       string `json:"keyId"`
	Kind        string `json:"kind"`
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	return !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) })
}
func ValidateContext(c Context) error {
	if c.Version != 1 || c.Revision == 0 || c.Revision > 9007199254740991 {
		return ErrInvalid
	}
	if c.Product != "momentum" && c.Product != "manifest" {
		return ErrInvalid
	}
	for _, value := range []string{c.AccountID, c.ResourceID, c.RecordID, c.KeyID, c.Kind} {
		if !validID(value) {
			return ErrInvalid
		}
	}
	if c.WorkspaceID != "" && !validID(c.WorkspaceID) {
		return ErrInvalid
	}
	return nil
}
func decoded(value string, max int) ([]byte, error) {
	if len(value) > (max*4+2)/3 {
		return nil, ErrInvalid
	}
	result, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(result) > max || base64.RawURLEncoding.EncodeToString(result) != value {
		return nil, ErrInvalid
	}
	return result, nil
}

// Validate rejects legacy plaintext and mismatched routing contexts. It cannot
// authenticate the GCM tag: client decryption does that; native admission binds
// exact routing/revision and the opaque payload digest at commit.
func Validate(e Envelope, c Context) error {
	if ValidateContext(c) != nil {
		return ErrInvalid
	}
	if e.Version != 1 || e.Algorithm != "AES-256-GCM" || e.KeyID != c.KeyID {
		return ErrInvalid
	}
	iv, err := decoded(e.IV, 12)
	if err != nil || len(iv) != 12 {
		return ErrInvalid
	}
	body, err := decoded(e.Ciphertext, MaxBytes+16)
	if err != nil || len(body) < 16 {
		return ErrInvalid
	}
	return nil
}

// Parse is strict and bounded, rejecting unknown fields, duplicate properties,
// trailing JSON, and missing envelope fields before accepting opaque bytes.
func Parse(raw []byte, c Context) (Envelope, error) {
	var e Envelope
	if len(raw) > (MaxBytes+16)*4/3+2048 {
		return e, ErrInvalid
	}
	if uniqueFields(raw) != nil {
		return e, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&e) != nil {
		return Envelope{}, ErrInvalid
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Envelope{}, ErrInvalid
	}
	if Validate(e, c) != nil {
		return Envelope{}, ErrInvalid
	}
	return e, nil
}
func uniqueFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err = decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return ErrInvalid
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return ErrInvalid
		}
	}
	if len(seen) != 5 {
		return ErrInvalid
	}
	return nil
}

// ParseContext validates the same required control shape as the browser AAD.
func ParseContext(raw []byte) (Context, error) {
	var c Context
	if len(raw) > 4096 {
		return c, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return c, ErrInvalid
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err = decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return c, ErrInvalid
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return c, ErrInvalid
		}
		if name == "workspaceId" && (bytes.Equal(value, []byte(`""`)) || bytes.Equal(value, []byte("null"))) {
			return c, ErrInvalid
		}
	}
	for _, name := range []string{"version", "accountId", "product", "resourceId", "recordId", "revision", "keyId", "kind"} {
		if !seen[name] {
			return c, ErrInvalid
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || decoder.Decode(new(any)) != io.EOF || ValidateContext(c) != nil {
		return Context{}, ErrInvalid
	}
	return c, nil
}
