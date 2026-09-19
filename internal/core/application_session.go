package core

// Only a keyed hash of each opaque credential is persisted. Session records
// remain backend state and are excluded from every user-facing node view.
type ApplicationSession struct {
	UserID    string `json:"user_id"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	// CredentialEpoch is the generation of the account's rules this session was minted under, read
	// back on every request it authenticates. A stored record could have been DELETED when the rules
	// changed instead — but a delete pass and a mint that is already in flight do not serialize
	// against each other, so a session opened in that window would survive the change it was supposed
	// to be caught by. Stamping costs nothing to check, because applicationSession already reads the
	// account's profile on every request to confirm it still exists.
	CredentialEpoch int64 `json:"credential_epoch,omitempty"`
}
