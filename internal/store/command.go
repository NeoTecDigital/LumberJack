// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Package store implements the resident, command-only persistence profile.
package store

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	ErrInvalid     = errors.New("invalid record command")
	ErrConflict    = errors.New("record revision or identity conflict")
	ErrDenied      = errors.New("record access denied")
	ErrAbsent      = errors.New("record not found")
	ErrUnavailable = errors.New("record durability unresolved")
)

const MaxEdits = 256
const MaxBytes = 1 << 20
const Root = "root"

type Expected struct {
	Revision *uint64 `json:"revision,omitempty"`
	Topology *uint64 `json:"topology,omitempty"`
}
type Command struct {
	ID       string              `json:"command_id"`
	Expected map[string]Expected `json:"expected,omitempty"`
	Edits    []Edit              `json:"edits"`
}
type Edit struct {
	Op     string          `json:"op"`
	ID     string          `json:"id,omitempty"`
	Kind   string          `json:"kind,omitempty"`
	Key    string          `json:"key,omitempty"`
	Value  json.RawMessage `json:"value,omitempty"`
	Parent string          `json:"parent,omitempty"`
	Child  string          `json:"child,omitempty"`
}
type Receipt struct {
	ID       string   `json:"command_id"`
	Sequence uint64   `json:"sequence"`
	Created  []string `json:"created,omitempty"`
}
type framedEdit struct {
	Edit
	Prefix  *int   `json:"entry_prefix"`
	RawSlot []byte `json:"raw_slot,omitempty"`
}
type frame struct {
	Version   int                 `json:"version"`
	Sequence  uint64              `json:"sequence"`
	Store     string              `json:"store"`
	Issuer    string              `json:"issuer"`
	CommandID string              `json:"command_id"`
	Digest    string              `json:"digest"`
	Expected  map[string]Expected `json:"expected,omitempty"`
	Edits     []framedEdit        `json:"edits"`
}

func Decode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func token(s string) bool {
	return len(s) > 0 && len(s) <= 256 && strings.TrimSpace(s) == s && !strings.ContainsRune(s, 0)
}
func semanticID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func parseCommand(raw []byte, receiptKey []byte) (Command, string, error) {
	var c Command
	if len(raw) > MaxBytes {
		return c, "", ErrInvalid
	}
	if err := Decode(raw, &c); err != nil {
		return c, "", err
	}
	if !token(c.ID) || len(c.Edits) < 1 || len(c.Edits) > MaxEdits || len(c.Expected) > 3*MaxEdits {
		return c, "", ErrInvalid
	}
	var shape struct {
		Edits []map[string]json.RawMessage `json:"edits"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return c, "", ErrInvalid
	}
	for i, e := range c.Edits {
		if err := checkEdit(e, shape.Edits[i]); err != nil {
			return c, "", err
		}
	}
	canonical, err := json.Marshal(c)
	if err != nil {
		return c, "", err
	}
	h := hmac.New(sha256.New, receiptKey)
	h.Write([]byte("record-command-v1\x00"))
	h.Write(canonical)
	// Preserve byte identity for opaque slot values, even where JSON encoding compacts them.
	for _, e := range c.Edits {
		if e.Op == "slot" {
			h.Write([]byte{0})
			h.Write(e.Value)
		}
	}
	return c, hex.EncodeToString(h.Sum(nil)), nil
}
func checkEdit(e Edit, fields map[string]json.RawMessage) error {
	allowed := map[string]string{"create": " kind id ", "field": " id key value ", "slot": " id key value ", "unset_field": " id key ", "unset_slot": " id key ", "append": " id value ", "link": " parent child ", "unlink": " parent child ", "delete": " id "}
	a, ok := allowed[e.Op]
	if !ok {
		return ErrInvalid
	}
	for k := range fields {
		if k != "op" && !strings.Contains(a, " "+k+" ") {
			return ErrInvalid
		}
	}
	switch e.Op {
	case "create":
		if !token(e.Kind) {
			return ErrInvalid
		}
		if _, ok := fields["id"]; ok && !semanticID(e.ID) {
			return ErrInvalid
		}
	case "link", "unlink":
		if !token(e.Parent) || !token(e.Child) {
			return ErrInvalid
		}
	default:
		if !token(e.ID) {
			return ErrInvalid
		}
	}
	if strings.Contains(a, " key ") && !token(e.Key) {
		return ErrInvalid
	}
	if strings.Contains(a, " value ") && len(e.Value) == 0 {
		return ErrInvalid
	}
	return nil
}
