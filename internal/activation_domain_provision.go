// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"fmt"
)

// DomainEnroll uses the existing paired state writer and retained lease channel.
func (s *Server) DomainEnroll(ctx context.Context, input EnrollmentInput) (DomainBegin, error) {
	d, err := s.domainEngine()
	if err != nil {
		return DomainBegin{}, err
	}
	raw, err := CanonicalDomainJSON(input)
	if err != nil {
		return DomainBegin{}, err
	}
	input, err = DecodeEnrollmentInput(raw, d.config.MaxRequestBytes)
	if err != nil {
		return DomainBegin{}, err
	}
	if _, err = d.enrollmentProfile(input.Request); err != nil {
		return DomainBegin{}, err
	}
	actor, err := d.verifyEnrollment(ctx, input, "admission", nil)
	if err != nil {
		return DomainBegin{}, err
	}
	entry, err := d.reserveEnrollment(actor, input)
	if err != nil {
		return DomainBegin{}, err
	}
	body, err := s.executeEnrollment(d, entry)
	return d.completeEnrollment(entry, body, err)
}
func (s *Server) executeEnrollment(d *domainEngine, entry *domainEntry) ([]byte, error) {
	command := s.enrollmentSourceCommand(d, entry)
	permit, err := s.sourceFence().beginWrite(context.Background(), sourceCommandKey(command))
	if err != nil {
		return nil, err
	}
	return s.executeEnrollmentWithPermit(d, entry, permit)
}
func (s *Server) executeEnrollmentWithPermit(d *domainEngine, entry *domainEntry, permit *sourceWritePermit) ([]byte, error) {
	actor := entry.enrollment.actor
	var prepared stagedPreparation
	var err error
	if actor.Request.Operation == EnrollmentProvision {
		prepared, err = s.prepareEnrollmentProvision(d, entry)
	} else {
		prepared, err = s.prepareEnrollmentACL(d, entry)
	}
	if err != nil {
		permit.noEffect(true)
		return nil, err
	}
	stamp, err := s.stateWriter.commitPaired(prepared.snapshot, prepared.pair)
	if err != nil {
		permit.finish(false, true)
		return nil, err
	}
	if err = s.publishOwnedPair(entry.owned.Binding.ScopeID, prepared.pending, stamp); err != nil {
		permit.finish(false, true)
		return nil, err
	}
	permit.finish(true, true)
	d.mu.Lock()
	entry.pendingKey = ""
	entry.pair = domainPair(entry, enrollmentCommand(actor, entry.owned.Binding), stamp)
	entry.receiptKey = stamp.Pair.Key
	d.rootGeneration++
	d.mu.Unlock()
	status := "applied"
	if prepared.replayed {
		status = "replayed"
	}
	return enrollmentResponse(entry, stamp, status)
}
func enrollmentResponse(entry *domainEntry, stamp stagedDurableStamp, status string) ([]byte, error) {
	return enrollmentResponseFields(entry, stamp.Pair.AfterRevision, status)
}
func enrollmentResponseFields(entry *domainEntry, revision, status string) ([]byte, error) {
	r := entry.enrollment.input.Request
	receipt := map[string]interface{}{"commandId": r.CommandID, "operation": r.Operation, "expectedRevision": r.ExpectedRevision, "requestFingerprint": entry.lease.IntentFingerprint, "status": status, "revision": revision, "binding": entry.lease.Binding, "profileRef": r.ProfileRef}
	if r.Administration != nil {
		receipt["ownerPrincipalId"] = r.Administration.OwnerPrincipalID
	}
	return CanonicalDomainJSON(map[string]interface{}{"contractRevision": r.ContractRevision, "requestId": entry.enrollment.input.RequestID, "scope": r.Scope, "receipt": receipt})
}
func (s *Server) prepareEnrollmentProvision(d *domainEngine, entry *domainEntry) (stagedPreparation, error) {
	s.forestMutex.Lock()
	defer s.forestMutex.Unlock()
	if err := d.enrollmentLive(entry); err != nil {
		return stagedPreparation{}, err
	}
	actor := entry.enrollment.actor
	scopeID := enrollmentScopeID(actor.Scope.AccountID)
	scope := s.stagedScopes[scopeID]
	if scope != nil {
		return s.prepareEnrollmentReplayLocked(d, entry, scope)
	}
	if _, present := d.lookupDomainScope(actor.Scope); present {
		return stagedPreparation{}, fmt.Errorf("existing native root cannot be adopted")
	}
	if !d.enrollmentCapacity() {
		return stagedPreparation{}, fmt.Errorf("dynamic scope capacity exhausted")
	}
	scope, pending, err := s.allocateEnrollmentRoots(d, actor)
	if err != nil {
		return stagedPreparation{}, err
	}
	d.bindEnrollmentEntry(entry, scope.descriptor, "")
	if err = validateEnrollmentResponseBound(d, entry, pending.receipt.AfterRevision); err != nil {
		d.clearEnrollmentPending(entry)
		return stagedPreparation{}, err
	}
	if s.stagedScopes == nil {
		s.stagedScopes = map[string]*stagedScope{}
	}
	scope.pending = pending
	s.stagedScopes[scopeID] = scope
	d.bindEnrollmentEntry(entry, scope.descriptor, pending.key)
	prepared, err := s.snapshotOwnedPreparationLocked(scope, pending, pending.key, false)
	if err != nil {
		delete(s.stagedScopes, scopeID)
		d.clearEnrollmentPending(entry)
	}
	return prepared, err
}
func (s *Server) prepareEnrollmentReplayLocked(d *domainEngine, entry *domainEntry, scope *stagedScope) (stagedPreparation, error) {
	if descriptorProfile(scope.descriptor) != entry.enrollment.input.Request.ProfileRef {
		return stagedPreparation{}, fmt.Errorf("protected profile history conflict")
	}
	command := enrollmentCommand(entry.enrollment.actor, scope.descriptor.Binding)
	key := stagedCommandKey(command)
	receipt, err := s.enrollmentHistoryLocked(scope, key)
	if err != nil {
		return stagedPreparation{}, err
	}
	if err = validateEnrollmentReplay(scope, receipt, entry.enrollment.actor); err != nil {
		return stagedPreparation{}, err
	}
	d.bindEnrollmentEntry(entry, scope.descriptor, "")
	if actor := entry.enrollment.actor; actor.Request.Administration != nil {
		if err = s.authorizeEnrollmentRootLocked(d, entry); err != nil {
			return stagedPreparation{}, err
		}
	}
	d.bindEnrollmentEntry(entry, scope.descriptor, key)
	return s.snapshotOwnedPreparationLocked(scope, scope.pending, key, true)
}
func (s *Server) enrollmentHistoryLocked(scope *stagedScope, key string) (stagedReceipt, error) {
	if scope.pending != nil {
		if scope.pending.key != key {
			return stagedReceipt{}, errStagedPending
		}
		return scope.pending.receipt, nil
	}
	index, err := stagedForestIndex(s.forest)
	if err != nil || index[scope.descriptor.Binding.RootID] == nil {
		return stagedReceipt{}, errStagedUnconfigured
	}
	raw, present := index[scope.descriptor.Binding.RootID].CommandReceipts[key]
	if !present {
		return stagedReceipt{}, fmt.Errorf("exact actor-keyed enrollment history absent")
	}
	var receipt stagedReceipt
	err = decodeStagedInternal(raw, &receipt)
	return receipt, err
}
func validateEnrollmentReplay(scope *stagedScope, receipt stagedReceipt, actor EnrollmentVerified) error {
	command := enrollmentCommand(actor, scope.descriptor.Binding)
	if receipt.Command != command || receipt.Fingerprint != stagedCommandFingerprint(scope.descriptor.Binding, command) {
		return apiErrorf(409, "command_conflict")
	}
	if err := validateEnrollmentReceipt(scope.descriptor.Binding, receipt, scope.descriptor.Bounds.MaxScopeBytes); err != nil {
		return err
	}
	if len(receipt.EnrollmentRecord) == 0 {
		return fmt.Errorf("enrollment provenance absent")
	}
	record, err := decodeEnrollmentRecord(receipt.EnrollmentRecord, scope.descriptor.Bounds.MaxScopeBytes)
	if err != nil {
		return err
	}
	if err := validateEnrollmentReplayActor(record, actor); err != nil {
		return err
	}
	if isEnrollmentGrantOperation(actor.Request.Operation) && (actor.PrincipalReference == nil || !domainEqual(record.TargetGrantRevision, actor.PrincipalReference.TargetGrantRevision)) {
		return fmt.Errorf("original target BASE revision revoked/replaced")
	}
	return nil
}

// Pure size check only: this body is never exposed or treated as durability evidence.
func validateEnrollmentResponseBound(d *domainEngine, entry *domainEntry, revision string) error {
	raw, err := enrollmentResponseFields(entry, revision, "replayed")
	if err != nil || len(raw) > d.config.MaxResponseBytes {
		return fmt.Errorf("configured response bound cannot hold actual enrollment receipt")
	}
	return nil
}
