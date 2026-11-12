// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package extension

import (
	"context"

	"github.com/NeoTecDigital/LumberJack/core"
)

// PermitProvider is consulted on EVERY write, ordinary or extension-issued, before the forest is
// taken. At most one is registered per runtime.
type PermitProvider interface {
	Acquire(ctx context.Context, op WriteOp) (Permit, error) // an error refuses the write, with no effect
}

// Permit is one write's permission, settled exactly once with its outcome.
type Permit interface {
	// WantsRevision asks the engine to compute the whole-forest revision before the change and again
	// after a refusal. Only an exclusive provider may ask: Unchanged means nothing if another writer
	// could interleave.
	WantsRevision() bool
	Settle(Outcome) // exactly once, with no forest hold and no writer mutex held
}

// OutcomeState is what became of a write. The names carry a Write prefix because Refused is also a
// RequestAuthenticator's Claim.
type OutcomeState uint8

const (
	WriteRefused OutcomeState = iota // the change returned an error under the hold
	WriteUnknown                     // the change was staged but could not be made durable
	WriteDurable                     // on disk (snapshot) or in the hot log (tiered)
)

// Outcome is a write's settled result.
type Outcome struct {
	State     OutcomeState
	Unchanged bool   // WriteRefused only, and only when WantsRevision: the revision is as before
	Commit    Commit // WriteDurable only
	Err       error
}

// WriteHook brackets every change under the exclusive hold, in both persistence modes.
type WriteHook interface {
	BeforeChangeLocked(tx Tx, op WriteOp) (After, error)
}

// After is called with the change's own error, even when that error is non-nil. A non-nil return
// vetoes the change (answered 403 unless it carries an *Error). The hook must restore whatever it
// protects before vetoing; the engine does not roll back.
type After func(tx Tx, changeErr error) error

// VisibilityFilter hides nodes from every GENERIC read. Extension reads through ReadTx are not
// filtered: the owner sees its own nodes.
type VisibilityFilter interface {
	HiddenLocked(n *core.Node) bool // under a shared or exclusive hold; pure, deterministic, O(1)
}
