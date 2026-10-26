// Package businessruntime joins verified authority, admission and ciphertext Raft records.
package businessruntime

import (
	"context"
	"errors"
	"github.com/NeoTecDigital/LumberJack/internal/admission"
	"github.com/NeoTecDigital/LumberJack/internal/ciphertext"
	"github.com/NeoTecDigital/LumberJack/internal/replication"
	"time"
)

var ErrDenied = errors.New("business runtime denied")
var ErrUnresolved = errors.New("business runtime authority transition unresolved")

// Actor is provided only by the existing authenticated adapter, never request JSON.
type Actor struct{ PrincipalID, SessionID string }
type Request struct {
	Actor                                      Actor
	Scope                                      replication.Scope
	ResourceID, RecordID, CommandID, Operation string
	ExpectedRevision                           uint64
}
type Access struct {
	Actor                           Actor
	Scope                           replication.Scope
	ResourceID, RecordID, CommandID string
}
type Authorization struct {
	Claims  admission.Claims
	Context ciphertext.Context
}
type FenceRequest struct {
	OperationID            string
	Scope                  replication.Scope
	PrincipalID, SessionID string
	Version                uint64
}

// CurrentAuthority must freshly validate verified Activation session/grant and
// native resource ACL. Return values are trusted state, not decoded proof echoes.
type CurrentAuthority interface {
	Resolve(context.Context, Request) (Authorization, error)
	AuthorizeRead(context.Context, Access) error
	AuthorizeFence(context.Context, FenceRequest) error
}
type Config struct {
	Replication replication.Config
	Verifier    *admission.Verifier
	Authority   CurrentAuthority
	Now         func() time.Time
}
type Runtime struct {
	node         *replication.Node
	verifier     *admission.Verifier
	authority    CurrentAuthority
	now          func() time.Time
	controlToken *byte
}
type gateContextKey struct{}
type commitInput struct {
	Request       Request
	Payload       []byte
	Authorization Authorization
}
type controlInput struct{ Token *byte }
type barrierRecord struct {
	OperationID string `json:"operationId"`
	PrincipalID string `json:"principalId"`
	SessionID   string `json:"sessionId"`
	Version     uint64 `json:"version"`
	Confirmed   bool   `json:"confirmed"`
}
