package businessruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/replication"
)

func barrierKey(p, s string) string {
	b, _ := json.Marshal([]string{p, s})
	h := sha256.Sum256(b)
	return "authority/v1/" + hex.EncodeToString(h[:])
}
func (r *Runtime) readBarrier(ctx context.Context, scope replication.Scope, p, s string) (barrierRecord, error) {
	record, ok, e := r.node.Read(ctx, scope, barrierKey(p, s))
	if e != nil {
		return barrierRecord{}, e
	}
	if !ok {
		return barrierRecord{}, ErrUnresolved
	}
	var b barrierRecord
	if json.Unmarshal(record.Payload, &b) != nil || b.PrincipalID != p || b.SessionID != s {
		return barrierRecord{}, ErrUnresolved
	}
	return b, nil
}
func (r *Runtime) controlWrite(ctx context.Context, f FenceRequest, b barrierRecord, revision uint64, step string) error {
	raw, _ := json.Marshal(b)
	h := sha256.Sum256([]byte(f.OperationID))
	id := "authority/v1/" + hex.EncodeToString(h[:]) + "/" + step
	c := replication.Command{Scope: f.Scope, CommandID: id, Operation: "authority_barrier_" + step, RecordKey: barrierKey(f.PrincipalID, f.SessionID), ExpectedRevision: revision, Payload: raw, PrincipalID: f.PrincipalID, SessionID: f.SessionID, BarrierVersion: f.Version}
	result, e := r.node.Apply(context.WithValue(ctx, gateContextKey{}, controlInput{r.controlToken}), c)
	if e != nil {
		return e
	}
	if result.Outcome != "committed" {
		return ErrUnresolved
	}
	return nil
}

// Fence is a trusted revocation/authority-generation port. Prepare refuses all
// admissions until the fence is quorum-committed and its exact generation confirmed.
// Unknown transitions remain prepared and retry only by the same OperationID.
func (r *Runtime) Fence(ctx context.Context, f FenceRequest) error {
	if f.OperationID == "" || f.PrincipalID == "" || f.SessionID == "" || f.Version == 0 || r.authority.AuthorizeFence(ctx, f) != nil {
		return ErrDenied
	}
	if e := r.node.Fence(ctx, f.Scope, f.PrincipalID, f.SessionID, f.Version); e != nil {
		return e
	}
	record, exists, e := r.node.Read(ctx, f.Scope, barrierKey(f.PrincipalID, f.SessionID))
	if e != nil {
		return e
	}
	var prior barrierRecord
	if exists {
		if json.Unmarshal(record.Payload, &prior) != nil {
			return ErrUnresolved
		}
		if prior.Version > f.Version || (prior.Version == f.Version && prior.OperationID != f.OperationID) {
			return ErrDenied
		}
		if prior.OperationID == f.OperationID && prior.Version == f.Version && prior.Confirmed {
			return r.controlWrite(ctx, f, prior, record.Revision-1, "confirm")
		}
	}
	b := barrierRecord{OperationID: f.OperationID, PrincipalID: f.PrincipalID, SessionID: f.SessionID, Version: f.Version}
	if prior.OperationID != f.OperationID || prior.Version != f.Version {
		if e = r.controlWrite(ctx, f, b, record.Revision, "prepare"); e != nil {
			return e
		}
	}
	return r.finishFence(ctx, f, b)
}
func (r *Runtime) finishFence(ctx context.Context, f FenceRequest, b barrierRecord) error {
	if e := r.node.Fence(ctx, f.Scope, f.PrincipalID, f.SessionID, f.Version); e != nil {
		return e
	}
	prepared, ok, e := r.node.Read(ctx, f.Scope, barrierKey(f.PrincipalID, f.SessionID))
	if e != nil {
		return e
	}
	if !ok {
		return ErrUnresolved
	}
	var current barrierRecord
	if json.Unmarshal(prepared.Payload, &current) != nil || current != b {
		return ErrUnresolved
	}
	b.Confirmed = true
	return r.controlWrite(ctx, f, b, prepared.Revision, "confirm")
}
