// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package extension

import (
	"context"
	"fmt"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// Host is the engine as an extension instance sees it. Every write goes through Change, which is the
// engine's one write path: the same permit, hooks, guard and durability as an engine route.
type Host interface {
	Read(fn func(ReadTx) error) error                                          // shared hold
	Change(ctx context.Context, op WriteOp, fn func(Tx) error) (Commit, error) // the one write path
	Publish(kind, path string)                                                 // mutation stream; call only after Change returned
	Sessions() Sessions
	Logger() types.Logger
}

// ReadTx is a view of the forest under a hold. A *core.Node obtained from it must not outlive the
// callback.
type ReadTx interface {
	Root() *core.Node
	NodeByID(id string) (*core.Node, bool)
	NodeByPath(path string) (*core.Node, error) // unfiltered; the owner's view
	Slot(nodeID, key string) (any, bool)        // a key this extension declared; OutboxSlots addresses OutboxKeys
	Permits(n *core.Node, userID string, want core.Permission) bool
}

// Tx is a ReadTx under the exclusive hold of one change.
type Tx interface {
	ReadTx
	SetSlot(nodeID, key string, v any) error // through the key's Codec, or v as json.RawMessage when it has none
	DeleteSlot(nodeID, key string)
	Enqueue(c core.OutboxChange) error            // a notification, in the same snapshot as the change
	EnqueueOutbound(m core.OutboundMessage) error // the external outbox, in the same snapshot as the change
}

// OutboxSlots is the node id Slot, SetSlot and DeleteSlot take to address a key declared in
// SlotSpec.OutboxKeys: a key inside the root's "correspondence" object rather than on a record.
const OutboxSlots = "lumberjack:outbox"

// WriteOp names a write for the permit provider and the hooks.
type WriteOp struct {
	Key    string // the caller's operation identity, e.g. a command hash; engine writes: "engine/<id>"
	Origin string // "" for engine routes, else the issuing extension's Name
}

// Commit is where a durable change landed.
type Commit struct {
	Tiered bool
	Seq    uint64   // snapshot sequence, or hot-log sequence when Tiered
	SHA256 [32]byte // the durable snapshot's payload hash (zero when Tiered)
	Path   string   // the state file
}

// Error is how a handler or a Change answers a status. The engine maps it to its own API error.
type Error struct {
	Status     int
	Message    string
	RetryAfter string
}

func (e *Error) Error() string { return fmt.Sprintf("%d: %s", e.Status, e.Message) }
