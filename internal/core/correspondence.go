package core

// A committed command produces one delivery identity, independent of transient
// stream cursors. Recipients are captured at commit and checked again at delivery
// and read time. No private content is copied into routing records.
type CorrespondenceChange struct {
	ID         string   `json:"id"`
	PinID      string   `json:"pin_id"`
	Path       string   `json:"path"`
	Actor      string   `json:"actor"`
	Operation  string   `json:"operation"`
	At         string   `json:"at"`
	Recipients []string `json:"recipients"`
}
type CorrespondenceNotification struct {
	Change CorrespondenceChange `json:"change"`
	ReadAt string               `json:"read_at,omitempty"`
}
type CorrespondenceState struct {
	Pending      map[string]CorrespondenceChange         `json:"pending"`
	Inbox        map[string][]CorrespondenceNotification `json:"inbox"`
	Delivered    uint64                                  `json:"delivered"`
	LastDelivery string                                  `json:"last_delivery,omitempty"`
	// Outbound is the messenger's EXTERNAL outbox: items destined for a channel off this portal
	// (SMS, today) that a future forward-dispatcher role drains and hands to a one-shot proxy. It is
	// distinct from Pending, which is user-to-user inbox delivery inside the forest. The engine only
	// ENQUEUES here; it wires no transport. Channel and Purpose are the routing marker the dispatcher
	// selects on. Records are backend state, excluded from every user-facing node projection.
	Outbound map[string]OutboundMessage `json:"outbound,omitempty"`
}

// OutboundMessage is one item queued for external delivery off the portal.
//
// It carries the PLAINTEXT payload transiently, because delivery needs it and the store that proves
// a code (MFAChallenge) deliberately holds only a hash — the two are separate on purpose. It is
// short-lived: ExpiresAt bounds how long the plaintext may sit in the outbox, and a sweep removes it
// even if no dispatcher ever drains it. The engine never logs Payload and never returns it to a
// client.
type OutboundMessage struct {
	ID          string `json:"id"`
	Channel     string `json:"channel"`
	Purpose     string `json:"purpose"`
	To          string `json:"to"`
	Payload     string `json:"payload"`
	ChallengeID string `json:"challenge_id,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	CreatedAt   int64  `json:"created_at"`
	ExpiresAt   int64  `json:"expires_at"`
}
