// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package core

import "encoding/json"

// AccountSecurity is backend-only state. The encrypted root resource protects
// secrets at rest; these records must never be included in user projections.
type AccountSecurity struct {
	TOTPSecret       string           `json:"totp_secret,omitempty"`
	TOTPLastStep     int64            `json:"totp_last_step,omitempty"`
	Passkeys         []AccountPasskey `json:"passkeys,omitempty"`
	RecoveryHashes   []string         `json:"recovery_hashes,omitempty"`
	VerifiedEmail    string           `json:"verified_email,omitempty"`
	RecoveryContacts []string         `json:"recovery_contacts,omitempty"`
}

type AccountPasskey struct {
	ID         string          `json:"id"`
	Label      string          `json:"label"`
	CreatedAt  int64           `json:"created_at"`
	Credential json.RawMessage `json:"credential"`
}
