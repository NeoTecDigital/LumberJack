// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"fmt"
	"math"
)

func (d *domainEngine) reserveEnrollment(actor EnrollmentVerified, input EnrollmentInput) (*domainEntry, error) {
	admission, err := d.source.reserveSession(enrollmentSessionKey{actor.PrincipalID, actor.SessionID}, d.config.MaxLeases)
	if err != nil {
		return nil, err
	}
	defer admission.release()
	d.mu.Lock()
	defer d.mu.Unlock()
	key := DomainGateKey{actor.PrincipalID, actor.SessionID, actor.Scope}
	if actor.ExpiresAt <= domainNow() || d.closed[key] || d.sessionFences[enrollmentSessionKey{actor.PrincipalID, actor.SessionID}] || len(d.entries) >= d.config.MaxLeases {
		return nil, fmt.Errorf("current enrollment gate closed/expired/full")
	}
	id, err := newDomainID()
	if err != nil {
		return nil, err
	}
	raw, err := canonicalEnrollmentRequest(input.Request, d.config.MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	lease := DomainLease{Epoch: d.epoch, LeaseID: id, PrincipalID: actor.PrincipalID, SessionID: actor.SessionID, Scope: actor.Scope, Binding: DomainBinding{Scope: actor.Scope}, IntentFingerprint: stagedHash(raw)}
	entry := &domainEntry{lease: lease, executing: true, enrollment: &enrollmentEntry{input: input, actor: actor, privateRequest: raw}}
	d.entries[id] = entry
	d.rootGeneration++
	return entry, nil
}
func (d *domainEngine) enrollmentLive(entry *domainEntry) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enrollmentLiveLocked(entry)
}
func (d *domainEngine) enrollmentLiveLocked(entry *domainEntry) error {
	key := DomainGateKey{entry.lease.PrincipalID, entry.lease.SessionID, entry.lease.Scope}
	if entry.enrollment == nil || entry.finished || entry.disposition != "" || d.closed[key] || d.sessionFences[enrollmentSessionKey{key.PrincipalID, key.SessionID}] || d.source.sessionFenced(enrollmentSessionKey{key.PrincipalID, key.SessionID}) || entry.enrollment.actor.ExpiresAt <= domainNow() {
		return fmt.Errorf("current enrollment lease authority fenced/expired")
	}
	return nil
}
func (d *domainEngine) completeEnrollment(entry *domainEntry, body []byte, cause error) (DomainBegin, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry.executing = false
	if cause == nil {
		cause = d.enrollmentLiveLocked(entry)
	}
	if cause != nil && entry.pendingKey != "" {
		return d.retainEnrollmentUnknownLocked(entry)
	}
	if cause != nil || len(body) > d.config.MaxResponseBytes {
		entry.body = nil
		entry.disposition = "irrevocably-discarded"
		entry.finished = entry.pendingKey == ""
		d.rootGeneration++
		return DomainBegin{}, domainResultError{cause: cause}
	}
	entry.body, entry.responseHash = body, stagedHash(body)
	return DomainBegin{Lease: entry.lease, ExchangeID: entry.lease.LeaseID, ResponseHash: entry.responseHash}, nil
}
func (s *Server) validateEnrollmentLease(d *domainEngine, entry *domainEntry, input DomainControl) (DomainControlResult, error) {
	d.mu.Lock()
	active := d.activeLocked(entry) && entry.pair != nil && entry.pendingKey == ""
	until := math.Min(input.ValidUntil, entry.enrollment.actor.ExpiresAt)
	d.mu.Unlock()
	if !active || input.LeaseBinding == nil || !domainEqual(*input.LeaseBinding, entry.lease) || input.PrincipalID != entry.lease.PrincipalID || input.SessionID != entry.lease.SessionID || input.RequestFingerprint != entry.lease.IntentFingerprint || !domainFinite(until) || until <= domainNow() {
		return DomainControlResult{}, fmt.Errorf("exact current enrollment lease/private request denied")
	}
	s.forestMutex.RLock()
	err := s.validateEnrollmentCurrentLocked(d, entry)
	s.forestMutex.RUnlock()
	if err != nil {
		return DomainControlResult{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.activeLocked(entry) || until <= domainNow() {
		return DomainControlResult{}, fmt.Errorf("enrollment lease validity changed")
	}
	return DomainControlResult{Value: map[string]interface{}{"leaseBinding": entry.lease, "requestFingerprint": entry.lease.IntentFingerprint, "validUntil": until}}, nil
}
func (s *Server) handoffEnrollment(ctx context.Context, d *domainEngine, entry *domainEntry, input DomainControl) (DomainControlResult, error) {
	d.mu.Lock()
	active := d.activeLocked(entry) && entry.pair != nil && entry.pendingKey == ""
	checkInput := entry.enrollment.input
	old := entry.enrollment.actor
	d.mu.Unlock()
	if !active {
		return DomainControlResult{}, fmt.Errorf("enrollment handoff inactive")
	}
	checkInput.Proof = input.Proof
	actor, err := d.verifyEnrollment(ctx, checkInput, "handoff", &entry.lease)
	if err != nil {
		return DomainControlResult{}, err
	}
	if !enrollmentActorSame(old, actor) || old.ExpiresAt <= domainNow() {
		return DomainControlResult{}, fmt.Errorf("owner/target changed or original enrollment expired")
	}
	d.mu.Lock()
	actor.ExpiresAt = math.Min(actor.ExpiresAt, old.ExpiresAt)
	entry.enrollment.actor = actor
	d.mu.Unlock()
	s.forestMutex.RLock()
	err = s.validateEnrollmentCurrentLocked(d, entry)
	s.forestMutex.RUnlock()
	if err != nil {
		return DomainControlResult{}, err
	}
	id, err := newDomainID()
	if err != nil {
		return DomainControlResult{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.activeLocked(entry) || actor.ExpiresAt <= domainNow() {
		return DomainControlResult{}, fmt.Errorf("enrollment handoff revoked/expired")
	}
	entry.permitID = id
	return DomainControlResult{Value: DomainPermit{d.epoch, entry.lease.LeaseID, id, entry.responseHash}}, nil
}

// Discard can reconcile only an actual already-published durable witness. It must
// never introduce another effect using a closed/expired historical owner proof.
func (s *Server) finishEnrollmentPending(entry *domainEntry) error {
	permit, err := s.sourceRecoveryPermit(entry.owned.Binding.ScopeID, entry.pendingKey)
	if err != nil {
		return err
	}
	err = s.finishEnrollmentWithPermit(entry)
	if err != nil {
		permit.finish(false, false)
		return err
	}
	permit.finish(true, true)
	return nil
}
func (s *Server) finishEnrollmentWithPermit(entry *domainEntry) error {
	s.forestMutex.Lock()
	scope := s.stagedScopes[entry.owned.Binding.ScopeID]
	if scope == nil {
		s.forestMutex.Unlock()
		return errStagedUnconfigured
	}
	prepared, err := s.snapshotOwnedPreparationLocked(scope, scope.pending, entry.pendingKey, true)
	s.forestMutex.Unlock()
	if err != nil {
		return err
	}
	witness, err := s.inspectEnrollmentPair(context.Background(), prepared.snapshot, prepared.pair, scope.descriptor.Bounds.MaxSnapshotBytes)
	if err != nil {
		return err
	}
	defer witness.close()
	return s.publishOwnedPair(entry.owned.Binding.ScopeID, prepared.pending, witness.stamp)
}

func (d *domainEngine) retainEnrollmentUnknownLocked(entry *domainEntry) (DomainBegin, error) {
	body, err := CanonicalDomainJSON(map[string]interface{}{"error": map[string]string{"code": "domain_unavailable", "outcome": "unknown"}})
	if err != nil || len(body) > d.config.MaxResponseBytes {
		return DomainBegin{}, fmt.Errorf("negative enrollment envelope exceeds configured bound")
	}
	entry.body, entry.responseHash = body, stagedHash(body)
	entry.pair = nil
	d.rootGeneration++
	return DomainBegin{Lease: entry.lease, ExchangeID: entry.lease.LeaseID, ResponseHash: entry.responseHash}, nil
}
