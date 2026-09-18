package core

// Only a keyed hash of each opaque credential is persisted. Session records
// remain backend state and are excluded from every user-facing node view.
type ApplicationSession struct {
	UserID    string `json:"user_id"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}
