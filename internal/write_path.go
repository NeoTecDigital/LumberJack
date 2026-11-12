// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/NeoTecDigital/LumberJack/extension"
)

// The write path's seams (docs/extension-api.md §4.1): the permit every write holds from before the
// hold until its outcome is known, the write hooks that bracket every change under the hold, and the
// built-in owned-subtree guard that runs first and last.

// engineWriteOp names a write an engine route makes.
func engineWriteOp() extension.WriteOp { return extension.WriteOp{Key: "engine/" + rand.Text()} }

// forestRevision is the whole-forest revision: the sha256 of the forest's node-table encoding. It is
// what a permit that asks for it compares before the change and after a refusal.
func (server *Server) forestRevision() string {
	server.forestMutex.RLock()
	defer server.forestMutex.RUnlock()
	return server.forestRevisionLocked()
}

func (server *Server) forestRevisionLocked() string {
	raw, err := encodeState(server.forest)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// acquirePermit takes the write's permit with no hold, and the revision before the change when the
// permit asks for it. Only a permit that asks pays for encoding the whole forest.
func (server *Server) acquirePermit(op extension.WriteOp) (extension.Permit, string, error) {
	permit, err := server.permitProvider().Acquire(context.Background(), op)
	if err != nil {
		return nil, "", err
	}
	if permit == nil {
		return nil, "", errors.New("lumberjack: a permit provider answered no permit")
	}
	if !permit.WantsRevision() {
		return permit, "", nil
	}
	return permit, server.forestRevision(), nil
}

// beforeHooksLocked runs every write hook's before, in registration order, and answers the afters. A
// hook that refuses refuses the write; the afters already taken are told so, with its error.
func (server *Server) beforeHooksLocked(op extension.WriteOp) ([]ownedAfter, error) {
	if server.extensions == nil {
		return nil, nil
	}
	afters := make([]ownedAfter, 0, len(server.extensions.hooks))
	for _, hook := range server.extensions.hooks {
		tx := forestTx{server: server, owner: hook.owner}
		after, err := hook.capability.BeforeChangeLocked(tx, op)
		if err != nil {
			refusal := hookRefusal(err)
			_ = runAfters(afters, refusal)
			return nil, refusal
		}
		afters = append(afters, ownedAfter{after: after, tx: tx})
	}
	return afters, nil
}

// ownedAfter is a hook's after, with the transaction its hook was handed.
type ownedAfter struct {
	after extension.After
	tx    forestTx
}

// afterHooksLocked runs the afters in reverse registration order, every one of them, with the
// change's own error. The first veto refuses the change.
func (server *Server) afterHooksLocked(afters []ownedAfter, changeErr error) error {
	return runAfters(afters, changeErr)
}

func runAfters(afters []ownedAfter, changeErr error) error {
	var veto error
	for index := len(afters) - 1; index >= 0; index-- {
		if afters[index].after == nil {
			continue
		}
		if err := afters[index].after(afters[index].tx, changeErr); err != nil && veto == nil {
			veto = hookRefusal(err)
		}
	}
	return veto
}

// hookRefusal is how a hook's error is answered: its own status when it carries an *Error, else 403.
func hookRefusal(err error) error {
	var status *extension.Error
	if errors.As(err, &status) {
		return extensionError(err)
	}
	return apiErrorf(http.StatusForbidden, "%v", err)
}

// ownedGuardCapture is one change's before-image of the owned subtrees. verifyLocked refuses a
// change that touched them, restoring them; restoreLocked puts them back unconditionally after a
// hook refused.
type ownedGuardCapture interface {
	verifyLocked() error
	restoreLocked()
}

// ownedGuarder captures the owned subtrees before a change.
type ownedGuarder interface {
	captureLocked(op extension.WriteOp) (ownedGuardCapture, error)
}

// permitProvider is the registered PermitProvider, or the open permit when there is none: with no
// provider there is nothing to wait for and nothing to tell, so the permit asks for no revision and
// its settlement goes nowhere.
func (server *Server) permitProvider() extension.PermitProvider {
	if server.extensions != nil && server.extensions.permits != nil {
		return server.extensions.permits
	}
	return openPermits{}
}

type openPermits struct{}

func (openPermits) Acquire(context.Context, extension.WriteOp) (extension.Permit, error) {
	return openPermit{}, nil
}

type openPermit struct{}

func (openPermit) WantsRevision() bool { return false }

func (openPermit) Settle(extension.Outcome) {}
