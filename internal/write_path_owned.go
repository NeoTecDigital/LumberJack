// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"

	"github.com/NeoTecDigital/LumberJack/extension"
)

// TEMPORARY (P3b-6). The source fence and the staged-scope protection, still in the tree, plugged
// into the write path's seams so the product suites exercise the new ordering before the product
// leaves. Both leave with the owned-scope subsystem at P3b-7, when the default permit and the
// marker-based guard take their place. This file wraps the existing functions; it ports nothing.

// permitProvider is the registered PermitProvider, else the source fence.
func (server *Server) permitProvider() extension.PermitProvider {
	if server.extensions != nil && server.extensions.permits != nil {
		return server.extensions.permits
	}
	return fencePermitProvider{server: server}
}

type fencePermitProvider struct{ server *Server }

func (provider fencePermitProvider) Acquire(ctx context.Context, _ extension.WriteOp) (extension.Permit, error) {
	operationID, err := newDomainID()
	if err != nil {
		return nil, sourceUnavailable()
	}
	permit, err := provider.server.sourceFence().beginOrdinaryWrite(ctx, "ordinary-forest/"+operationID)
	if err != nil {
		return nil, err
	}
	return fencePermit{permit: permit}, nil
}

// fencePermit is an ordinary write's fence permit. Only a fenced one asks for the revision.
type fencePermit struct{ permit *sourceOrdinaryPermit }

func (fence fencePermit) WantsRevision() bool { return fence.permit.fenced() }

func (fence fencePermit) Settle(outcome extension.Outcome) {
	switch outcome.State {
	case extension.WriteRefused:
		fence.permit.noEffect(outcome.Unchanged)
	case extension.WriteUnknown:
		fence.permit.finish(false, true)
	default:
		fence.permit.finish(true, true)
	}
}

// ownedGuard is the staged-scope protection as the owned-subtree guard.
func (server *Server) ownedGuard() ownedGuarder { return stagedGuarder{server: server} }

type stagedGuarder struct{ server *Server }

func (guarder stagedGuarder) captureLocked(extension.WriteOp) (ownedGuardCapture, error) {
	protected, err := guarder.server.captureStagedProtectionLocked()
	if err != nil {
		return nil, err
	}
	return stagedGuardCapture{server: guarder.server, protected: protected}, nil
}

type stagedGuardCapture struct {
	server    *Server
	protected []stagedProtection
}

func (capture stagedGuardCapture) verifyLocked() error {
	return capture.server.verifyStagedProtectionLocked(capture.protected)
}

// restoreLocked puts the scopes back: the protection restores whatever a refused change touched.
func (capture stagedGuardCapture) restoreLocked() {
	_ = capture.server.verifyStagedProtectionLocked(capture.protected)
}
