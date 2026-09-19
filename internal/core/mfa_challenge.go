package core

// MFAChallenge is one pending second factor, keyed by challenge id on the forest.
//
// Only a keyed hash of the code is persisted — never the code — for the same reason
// ApplicationSession stores a hash of the credential: a reader of the state file must not be able to
// replay it into a completed login. Attempts is the per-challenge lockout counter, and ExpiresAt is
// the short TTL a sweep enforces, so an unfinished challenge cannot be brute-forced and does not
// outlive the login it belongs to. Records here remain backend state and are excluded from every
// user-facing node projection.
// DELIVERY IS A SEPARATE VERDICT FROM VERIFICATION, and the four fields below are where it is kept.
// Attempts counts GUESSES — how many wrong codes were typed — and says nothing about whether a code
// ever reached a phone. Without a second verdict the two failures are one shape: a challenge whose
// code the carrier refused looks exactly like a challenge whose code is sitting unread on somebody's
// phone, so the only thing either could be told was "invalid code", and the person who never got one
// waited for a text that was given up on sixty seconds ago.
//
// Delivery is "" while an item is still queued, "sent" once a carrier accepted it, and "failed" once
// the forward-dispatcher gave up. DeliveryError is the adapter's coarse class ("auth", "timeout",
// "provider_5xx", ...) and DeliveryTries the attempt count — BOTH FOR AN OPERATOR, not for a client;
// the wire answer carries the state alone. None of the three is ever a phone number or a code.
//
// HOW MANY TIMES A CODE WENT OUT is the last pair, and it is here rather than derived because the
// outbox cannot answer it: enqueueOutboundMFA writes each new code over the last one at the same key,
// so the outbox holds the CURRENT code and no memory of the ones before it. Sends counts every code
// this challenge has put on the wire, the first one included, and LastSendAt is when the most recent
// one went. application_mfa_resend.go is the only thing that reads them and says what they mean.
//
// BOTH ZERO VALUES ARE TRUE, which is why neither needs a migration: a challenge cannot exist
// without the send that created it, so Sends == 0 reads as one send and LastSendAt == 0 reads as
// CreatedAt — which is exactly when that one send happened.
type MFAChallenge struct {
	UserID        string `json:"user_id"`
	CodeHash      string `json:"code_hash"`
	Attempts      int    `json:"attempts"`
	CreatedAt     int64  `json:"created_at"`
	ExpiresAt     int64  `json:"expires_at"`
	Delivery      string `json:"delivery,omitempty"`
	DeliveryError string `json:"delivery_error,omitempty"`
	DeliveryTries int    `json:"delivery_tries,omitempty"`
	DeliveryAt    int64  `json:"delivery_at,omitempty"`
	Sends         int    `json:"sends,omitempty"`
	LastSendAt    int64  `json:"last_send_at,omitempty"`
}
