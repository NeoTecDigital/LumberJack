// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package extension

import "github.com/NeoTecDigital/LumberJack/core"

// OutboxListener learns an outbound item's fate from outbound_ack / outbound_failed, under the
// exclusive hold of that op. This is how a second factor marks its challenge "sent". It answers
// whether it recorded the outcome against something it owns.
type OutboxListener interface {
	OutboundSettledLocked(tx Tx, item core.OutboundMessage, outcome OutboundOutcome) bool
}

// OutboundState is what happened to an outbound item.
type OutboundState string

const (
	OutboundSent    OutboundState = "sent"    // a carrier took it
	OutboundExpired OutboundState = "expired" // its window closed unsent; cleared, nothing to mark
	OutboundFailed  OutboundState = "failed"  // the dispatcher gave up
)

// OutboundOutcome is one settled outbound item's verdict.
type OutboundOutcome struct {
	State      OutboundState
	ErrorClass string // the coarse failure class, for OutboundFailed
	Attempts   int
}

// OutboxEntitlement lets an extension vouch that a recipient is still entitled to a notification
// the generic rule would hide: a record written without Direct, before the flag existed. The
// generic rule is: the recipient can still read the node, and the record is Direct, or a share, or
// the recipient subscribes to the node, or an entitlement vouches.
type OutboxEntitlement interface {
	EntitledLocked(tx ReadTx, n core.OutboxNotification, userID string) bool
}
