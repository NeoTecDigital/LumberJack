// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/types"
)

// extensionHost is the engine as one extension instance sees it. Change is changeForest, the one
// write path; Read is readForest. Neither may be called from inside a locked callback.

var errExtensionsClosed = errors.New("lumberjack: the runtime's extensions are closed")

const (
	maxEventKindBytes  = 256
	maxEventScopeBytes = 512
)

type extensionHost struct {
	server *Server
	name   string
}

func (host *extensionHost) Read(fn func(extension.ReadTx) error) error {
	if host.server.extensionsClosed.Load() {
		return errExtensionsClosed
	}
	var err error
	host.server.readForest(func() { err = fn(forestTx{server: host.server, owner: host.name}) })
	return err
}

// Change runs fn as one change through the engine's write path, with the operation identity the
// permit provider and the write hooks see, its Origin set to this extension's name.
func (host *extensionHost) Change(ctx context.Context, op extension.WriteOp, fn func(extension.Tx) error) (extension.Commit, error) {
	if host.server.extensionsClosed.Load() {
		return extension.Commit{}, errExtensionsClosed
	}
	if err := ctx.Err(); err != nil {
		return extension.Commit{}, err
	}
	op.Origin = host.name
	return host.server.changeForestOp(op, func() error {
		return extensionError(fn(forestTx{server: host.server, owner: host.name}))
	})
}

func (host *extensionHost) Publish(kind, path string) {
	host.server.publish(mutation(kind, path))
}

func (host *extensionHost) PublishScoped(kind, scope string, payload json.RawMessage) error {
	if host.server.extensionsClosed.Load() {
		return errExtensionsClosed
	}
	if host.name == "" {
		return errors.New("lumberjack: scoped publish requires an extension owner")
	}
	if !validEventKind(kind) {
		return errors.New("lumberjack: invalid scoped event kind")
	}
	if !validEventScope(scope) {
		return errors.New("lumberjack: invalid scoped event scope")
	}
	if len(payload) == 0 || len(payload) > extension.MaxEventPayloadBytes {
		return errors.New("lumberjack: scoped event payload must be 1..4096 bytes")
	}
	if !json.Valid(payload) {
		return errors.New("lumberjack: scoped event payload is not valid JSON")
	}
	cloned := append(json.RawMessage(nil), payload...)
	host.server.publish(scopedMutation(host.name, kind, scope, cloned))
	return nil
}

func validEventKind(kind string) bool {
	if len(kind) == 0 || len(kind) > maxEventKindBytes {
		return false
	}
	for i := 0; i < len(kind); i++ {
		if kind[i] <= 0x20 || kind[i] == 0x7f {
			return false
		}
	}
	return true
}

func validEventScope(scope string) bool {
	if len(scope) == 0 || len(scope) > maxEventScopeBytes {
		return false
	}
	for i := 0; i < len(scope); i++ {
		if scope[i] < 0x20 || scope[i] == 0x7f {
			return false
		}
	}
	return true
}

// canDeliverScopedLocked reports whether a scoped mutation event may be delivered to userID under
// the caller's shared or exclusive forest hold. Missing owners, missing checks, errors and panics
// all fail closed.
func (s *Server) canDeliverScopedLocked(event mutationEvent, userID string) (deliver bool) {
	if !event.isScoped() || userID == "" || s.extensions == nil || s.extensionsClosed.Load() {
		return false
	}
	check := s.extensions.eventDelivery[event.extensionOwner]
	if check == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			deliver = false
		}
	}()
	payload := append(json.RawMessage(nil), event.Payload...)
	ok, err := check(forestTx{server: s, owner: event.extensionOwner}, userID, event.scope, payload)
	return err == nil && ok
}

func (host *extensionHost) Sessions() extension.Sessions {
	return extensionSessions{server: host.server}
}

func (host *extensionHost) Logger() types.Logger { return host.server.logger }

// extensionError maps an extension's *Error to the engine's own status error.
func extensionError(err error) error {
	var status *extension.Error
	if errors.As(err, &status) {
		mapped := apiErrorf(status.Status, "%s", status.Message)
		mapped.retryAfter = status.RetryAfter
		return mapped
	}
	return err
}

// forestTx is the forest under the hold a Read or Change took. It is the owner's view: nothing is
// filtered.
type forestTx struct {
	server *Server
	owner  string // the extension whose transaction this is; "" for the engine's own
}

func (tx forestTx) Root() *core.Node { return tx.server.forest }

func (tx forestTx) NodeByID(id string) (*core.Node, bool) {
	var found *core.Node
	walkForest(tx.server.forest, func(node *core.Node, _ []string) {
		if found == nil && node.ID == id {
			found = node
		}
	})
	return found, found != nil
}

func (tx forestTx) NodeByPath(path string) (*core.Node, error) {
	node, found := walkNames(tx.server.forest, tx.server.segmentsFrom(path))
	if !found {
		return nil, &extension.Error{Status: http.StatusNotFound, Message: "node not found: " + path}
	}
	return node, nil
}

func (tx forestTx) Permits(node *core.Node, userID string, want core.Permission) bool {
	return node != nil && node.CheckPermission(userID, want)
}

// EnqueueOutbound adds an item to the external outbox in the same snapshot as the change. An id
// already queued is refused, so an item cannot silently replace another.
func (tx forestTx) EnqueueOutbound(message core.OutboundMessage) error {
	if message.ID == "" {
		return &extension.Error{Status: http.StatusBadRequest, Message: "an outbound item needs an id"}
	}
	state := tx.server.correspondenceState()
	if state.Outbound == nil {
		state.Outbound = map[string]core.OutboundMessage{}
	}
	if _, queued := state.Outbound[message.ID]; queued {
		return &extension.Error{Status: http.StatusConflict, Message: "outbound item " + message.ID + " is already queued"}
	}
	state.Outbound[message.ID] = message
	return nil
}

// Enqueue records a notification in the same snapshot as the change.
func (tx forestTx) Enqueue(change core.OutboxChange) error {
	return tx.server.enqueueOutboxLocked(change)
}
