// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

package canon

import (
	"errors"
	"fmt"
)

// Code names why a value was refused. The set is the specification's and the names are the
// corpus's, so a refusal here compares with one from another reader by name.
type Code uint8

const (
	// DuplicateField is two NFC-equal field names in one record, in one id_from, or among the
	// fields an id_from name selects.
	DuplicateField Code = iota + 1
	// DuplicateMapKey is two canonically-equal keys in one map.
	DuplicateMapKey
	// UnknownIdentityField is an id_from name no field carries, present or absent.
	UnknownIdentityField
	// NestingTooDeep is a node deeper than MaxDepth.
	NestingTooDeep
)

var codeNames = map[Code]string{
	DuplicateField:       "duplicate_field",
	DuplicateMapKey:      "duplicate_map_key",
	UnknownIdentityField: "unknown_identity_field",
	NestingTooDeep:       "nesting_too_deep",
}

// String is the corpus name of the code.
func (c Code) String() string {
	if name, known := codeNames[c]; known {
		return name
	}
	return fmt.Sprintf("code(%d)", uint8(c))
}

// ParseCode maps a corpus error name back to its Code.
func ParseCode(name string) (Code, bool) {
	for code, known := range codeNames {
		if known == name {
			return code, true
		}
	}
	return 0, false
}

// Error is a refusal: which rule, and where it tripped.
type Error struct {
	Code   Code
	Detail string
}

func (e *Error) Error() string { return "canon: " + e.Code.String() + ": " + e.Detail }

func refuse(code Code, format string, args ...any) error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// CodeOf reports the refusal code err carries, if it is a refusal at all.
func CodeOf(err error) (Code, bool) {
	var refusal *Error
	if errors.As(err, &refusal) {
		return refusal.Code, true
	}
	return 0, false
}
