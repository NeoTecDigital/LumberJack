// Written by Richard Christopher, Copyright 2026 Mindfull
package ciphertext

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func fixture() (Envelope, Context) {
	c := Context{Version: 1, AccountID: "alice", Product: "momentum", ResourceID: "conversation", RecordID: "message", Revision: 1, KeyID: "epoch-1", Kind: "body"}
	e := Envelope{Version: 1, Algorithm: "AES-256-GCM", KeyID: c.KeyID,
		IV: base64.RawURLEncoding.EncodeToString(make([]byte, 12)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16))}
	return e, c
}
func TestOpaqueValidation(t *testing.T) {
	e, c := fixture()
	if Validate(e, c) != nil {
		t.Fatal("valid opaque envelope refused")
	}
	raw, _ := json.Marshal(e)
	if _, err := Parse(raw, c); err != nil {
		t.Fatal(err)
	}
	e.KeyID = "epoch-2"
	if Validate(e, c) == nil {
		t.Fatal("key epoch substitution accepted")
	}
}
func TestStrictParser(t *testing.T) {
	e, c := fixture()
	raw, _ := json.Marshal(e)
	cases := [][]byte{
		[]byte(`{"plaintext":"secret"}`),
		append(append([]byte{}, raw...), raw...),
		append([]byte(`{"version":1,`), raw[1:]...),
		append([]byte(`{"unknown":true,`), raw[1:]...),
	}
	for _, value := range cases {
		if _, err := Parse(value, c); err == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
	e.IV += "="
	if Validate(e, c) == nil {
		t.Fatal("padded base64 accepted")
	}
}
func TestInvalidContextAndLimits(t *testing.T) {
	e, c := fixture()
	c.Revision = 0
	if Validate(e, c) == nil {
		t.Fatal("missing revision accepted")
	}
	_, c = fixture()
	c.Product = "unknown"
	if Validate(e, c) == nil {
		t.Fatal("unknown product accepted")
	}
	_, c = fixture()
	e.Ciphertext = base64.RawURLEncoding.EncodeToString(make([]byte, MaxBytes+17))
	if Validate(e, c) == nil {
		t.Fatal("oversize accepted")
	}
}
