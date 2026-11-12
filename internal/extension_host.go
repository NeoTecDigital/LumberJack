// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"errors"
	"net/http"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/types"
)

// extensionHost is the engine as one extension instance sees it. Change is changeForest, the one
// write path; Read is readForest. Neither may be called from inside a locked callback.

var errExtensionsClosed = errors.New("lumberjack: the runtime's extensions are closed")

type extensionHost struct {
	server *Server
	name   string
}

func (host *extensionHost) Read(fn func(extension.ReadTx) error) error {
	if host.server.extensionsClosed.Load() {
		return errExtensionsClosed
	}
	var err error
	host.server.readForest(func() { err = fn(forestTx{server: host.server}) })
	return err
}

// Change runs fn as one change through the engine's write path. The operation identity reaches the
// permit provider and the write hooks once they are called (docs/extension-api.md §4.1).
func (host *extensionHost) Change(ctx context.Context, _ extension.WriteOp, fn func(extension.Tx) error) (extension.Commit, error) {
	if host.server.extensionsClosed.Load() {
		return extension.Commit{}, errExtensionsClosed
	}
	if err := ctx.Err(); err != nil {
		return extension.Commit{}, err
	}
	return host.server.changeForestCommit(func() error { return extensionError(fn(forestTx{server: host.server})) })
}

func (host *extensionHost) Publish(kind, path string) {
	host.server.publish(mutation(kind, path))
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
