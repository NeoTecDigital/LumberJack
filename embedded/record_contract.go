// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import "github.com/NeoTecDigital/LumberJack/internal/store"

// Record errors are stable categories for errors.Is; operating-system errors remain distinct.
var (
	ErrRecordInvalid     = store.ErrInvalid     // malformed or unsupported input
	ErrRecordDenied      = store.ErrDenied      // the principal lacks authority
	ErrRecordConflict    = store.ErrConflict    // incompatible state or command intent
	ErrRecordAbsent      = store.ErrAbsent      // the requested record does not exist
	ErrRecordUnavailable = store.ErrUnavailable // closed or fenced store
)

// MaxRecordRequestBytes bounds a record request before copying it across a binding.
const MaxRecordRequestBytes = store.MaxBytes

// OpenRecordDocument opens a store from the strict, versioned record ABI document.
// Version 1 does not accept version 2 fields.
func OpenRecordDocument(version uint32, raw []byte) (*RecordHandle, error) {
	if (version != 1 && version != 2) || len(raw) > MaxRecordRequestBytes {
		return nil, ErrRecordInvalid
	}
	type baseConfig struct {
		Directory  string `json:"directory"`
		Name       string `json:"name"`
		Principal  string `json:"principal"`
		Durability string `json:"durability"`
	}
	var r struct {
		baseConfig
		Indexes  []RecordIndex `json:"indexes,omitempty"`
		ReadOnly bool          `json:"read_only,omitempty"`
	}
	var target any = &r.baseConfig
	if version == 2 {
		target = &r
	}
	if err := store.Decode(raw, target); err != nil || r.Durability != "local-sync" {
		return nil, ErrRecordInvalid
	}
	return OpenIndexedRecords(r.Directory, r.Name, r.Principal, r.Indexes, r.ReadOnly)
}
