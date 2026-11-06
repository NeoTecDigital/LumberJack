package businessruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/admission"
	"github.com/NeoTecDigital/LumberJack/internal/ciphertext"
	"github.com/NeoTecDigital/LumberJack/internal/replication"
	"strconv"
	"strings"
)

// Open constructs an injected SDK foundation, NOT a production-certified service.
// Peer authentication must be integrated and verified before business activation.
func Open(c Config) (*Runtime, error) {
	if c.Verifier == nil || c.Authority == nil || c.Now == nil {
		return nil, ErrDenied
	}
	r := &Runtime{verifier: c.Verifier, authority: c.Authority, now: c.Now, controlToken: new(byte)}
	c.Replication.Gate = r.gate
	n, e := replication.Open(c.Replication)
	if e != nil {
		return nil, e
	}
	r.node = n
	return r, nil
}
func dataKey(resource, record string) string {
	b, _ := json.Marshal([]string{resource, record})
	h := sha256.Sum256(b)
	return "ciphertext/v1/" + hex.EncodeToString(h[:])
}
func sameScope(a admission.Scope, b replication.Scope) bool {
	return a.AccountID == b.AccountID && a.Product == b.Product && a.WorkspaceID == b.WorkspaceID
}
func validAuthorization(in Request, a Authorization) bool {
	c := a.Claims
	x := a.Context
	return c.PrincipalID == in.Actor.PrincipalID && c.SessionID == in.Actor.SessionID && sameScope(c.Scope, in.Scope) && c.ResourceID == in.ResourceID && c.CommandID == in.CommandID && c.Operation == in.Operation && c.ResourceRevision == strconv.FormatUint(in.ExpectedRevision, 10) && x.AccountID == in.Scope.AccountID && x.Product == in.Scope.Product && x.WorkspaceID == in.Scope.WorkspaceID && x.ResourceID == in.ResourceID && x.RecordID == in.RecordID && in.ExpectedRevision < 9007199254740991 && x.Revision == in.ExpectedRevision+1
}
func (r *Runtime) Commit(ctx context.Context, in Request, proof, payload []byte) (replication.Result, error) {
	if strings.HasPrefix(in.CommandID, "authority/v1/") {
		return replication.Result{}, ErrDenied
	}
	a, e := r.authority.Resolve(ctx, in)
	if e != nil || !validAuthorization(in, a) {
		return replication.Result{}, ErrDenied
	}
	if _, e = ciphertext.Parse(payload, a.Context); e != nil {
		return replication.Result{}, ErrDenied
	}
	digest := sha256.Sum256(payload)
	if a.Claims.BodySHA256 != hex.EncodeToString(digest[:]) {
		return replication.Result{}, ErrDenied
	}
	c := replication.Command{Scope: in.Scope, CommandID: in.CommandID, Operation: in.Operation, RecordKey: dataKey(in.ResourceID, in.RecordID), ExpectedRevision: in.ExpectedRevision, Payload: append(json.RawMessage(nil), payload...), PrincipalID: in.Actor.PrincipalID, SessionID: in.Actor.SessionID, BarrierVersion: a.Claims.BarrierVersion, Admission: append(json.RawMessage(nil), proof...)}
	ctx = context.WithValue(ctx, gateContextKey{}, commitInput{in, append([]byte(nil), payload...), a})
	return r.node.Apply(ctx, c)
}
func (r *Runtime) gate(ctx context.Context, c replication.Command, current uint64) error {
	if control, ok := ctx.Value(gateContextKey{}).(controlInput); ok {
		if control.Token == r.controlToken && current == c.BarrierVersion {
			return nil
		}
		return ErrDenied
	}
	input, ok := ctx.Value(gateContextKey{}).(commitInput)
	if !ok {
		return ErrDenied
	}
	fresh, e := r.authority.Resolve(ctx, input.Request)
	if e != nil || fresh != input.Authorization || !validAuthorization(input.Request, fresh) || current != fresh.Claims.BarrierVersion {
		return ErrDenied
	}
	barrier, e := r.readBarrier(ctx, c.Scope, c.PrincipalID, c.SessionID)
	if e != nil {
		return ErrDenied
	}
	_, e = r.verifier.Verify(c.Admission, fresh.Claims, input.Payload, r.now().Unix(), func(admission.Scope, string, string) (admission.Barrier, error) {
		return admission.Barrier{Version: barrier.Version, Confirmed: barrier.Confirmed}, nil
	})
	if e != nil {
		return ErrDenied
	}
	return nil
}
func (r *Runtime) Read(ctx context.Context, a Access) (replication.Record, bool, error) {
	if a.ResourceID == "" || a.RecordID == "" || r.authority.AuthorizeRead(ctx, a) != nil {
		return replication.Record{}, false, ErrDenied
	}
	record, ok, e := r.node.Read(ctx, a.Scope, dataKey(a.ResourceID, a.RecordID))
	if e != nil {
		return replication.Record{}, false, e
	}
	if r.authority.AuthorizeRead(ctx, a) != nil {
		return replication.Record{}, false, ErrDenied
	}
	return record, ok, nil
}
func (r *Runtime) Receipt(ctx context.Context, a Access) (replication.Result, bool, error) {
	if a.ResourceID == "" || a.CommandID == "" || strings.HasPrefix(a.CommandID, "authority/v1/") || r.authority.AuthorizeRead(ctx, a) != nil {
		return replication.Result{}, false, ErrDenied
	}
	result, ok, e := r.node.Receipt(ctx, a.Scope, a.CommandID)
	if e != nil {
		return replication.Result{}, false, e
	}
	if r.authority.AuthorizeRead(ctx, a) != nil {
		return replication.Result{}, false, ErrDenied
	}
	return result, ok, nil
}
func (r *Runtime) Close() error { return r.node.Close() }
