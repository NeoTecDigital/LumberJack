package core

// MFAChallenge is one pending second factor, keyed by challenge id on the forest.
//
// Only a keyed hash of the code is persisted — never the code — for the same reason
// ApplicationSession stores a hash of the credential: a reader of the state file must not be able to
// replay it into a completed login. Attempts is the per-challenge lockout counter, and ExpiresAt is
// the short TTL a sweep enforces, so an unfinished challenge cannot be brute-forced and does not
// outlive the login it belongs to. Records here remain backend state and are excluded from every
// user-facing node projection.
type MFAChallenge struct {
	UserID    string `json:"user_id"`
	CodeHash  string `json:"code_hash"`
	Attempts  int    `json:"attempts"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}
