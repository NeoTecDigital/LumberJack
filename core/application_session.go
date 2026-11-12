// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package core

// Only a keyed hash of each opaque credential is persisted. Session records
// remain backend state and are excluded from every user-facing node view.
type ApplicationSession struct {
	UserID       string `json:"user_id"`
	CreatedAt    int64  `json:"created_at"`
	ExpiresAt    int64  `json:"expires_at"`
	LastActiveAt int64  `json:"last_active_at,omitempty"`
	MFAAt        int64  `json:"mfa_at,omitempty"`
	DeviceName   string `json:"device_name,omitempty"`
	// CredentialEpoch is the generation of the account's rules this session was minted under, read
	// back on every request it authenticates. A stored record could have been DELETED when the rules
	// changed instead — but a delete pass and a mint that is already in flight do not serialize
	// against each other, so a session opened in that window would survive the change it was supposed
	// to be caught by. Stamping costs nothing to check, because applicationSession already reads the
	// account's profile on every request to confirm it still exists.
	CredentialEpoch int64 `json:"credential_epoch,omitempty"`
	// Delegated marks a session minted from a signed admission (POST /session/admit), not from this
	// engine's own password and factors, which it does not owe. SourceSession is the account
	// authority's session that admission was issued from; sign-out ends every lease it holds.
	Delegated     bool   `json:"delegated,omitempty"`
	SourceSession string `json:"source_session,omitempty"`
}
