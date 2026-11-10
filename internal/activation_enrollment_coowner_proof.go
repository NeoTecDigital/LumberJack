// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"fmt"
)

func enrollmentProofPhase(input EnrollmentInput, phase string, lease *DomainLease) bool {
	if (phase == "admission") != (lease == nil) {
		return false
	}
	if !enrollmentCoownerRequest(input.Request) {
		return phase == "admission" || phase == "handoff"
	}
	if input.Mode == "receipt" {
		return phase == "handoff"
	}
	return phase == "admission" || phase == "handoff" || phase == "precommit" && input.Mode == "apply"
}

func (d *domainEngine) coownerCheckWire(input EnrollmentInput, fingerprint string) *EnrollmentCoownerWire {
	if !enrollmentCoownerRequest(input.Request) {
		return nil
	}
	if input.Mode == "inspect" && input.ReceiptActorPrincipalID != nil {
		fingerprint = coownerInspectionFingerprint(input.Request, *input.ReceiptActorPrincipalID)
	}
	return &EnrollmentCoownerWire{input.Mode, input.ReceiptActorPrincipalID, fingerprint, input.ReceiptBinding, d.config.HostID}
}

func (d *domainEngine) validCoownerActor(actor EnrollmentVerified, check EnrollmentCheck) bool {
	now := domainNow()
	p, err := d.enrollmentProfile(actor.Request)
	if err != nil || actor.ContractRevision != EnrollmentCoownerProofRevision || actor.Kind != "human" || actor.AdministratorAuthorized {
		return false
	}
	if enrollmentIdentifiers(p.Bounds.MaxIdentifierBytes, actor.PrincipalID, actor.SessionID, actor.GrantRevision, actor.AuthorityPolicyRevision, actor.AuthorityResourceRevision) != nil {
		return false
	}
	if actor.Issuer != d.config.Trust.Issuer || actor.Audience != check.Audience || actor.Purpose != check.Request.Operation || actor.Phase != check.Phase || actor.ProofBinding != stagedHash([]byte(check.Proof)) {
		return false
	}
	if actor.Scope != check.Request.Scope || actor.RequestID != check.RequestID || actor.RequestFingerprint != check.RequestFingerprint || !domainEqual(actor.Request, check.Request) || !domainEqual(actor.LeaseBinding, check.LeaseBinding) {
		return false
	}
	if actor.EnrollmentCoownerWire == nil || !domainEqual(actor.EnrollmentCoownerWire, check.EnrollmentCoownerWire) || actor.NativeHostID != d.config.HostID {
		return false
	}
	if !domainFinite(actor.ExpiresAt) || actor.ExpiresAt <= now || actor.ExpiresAt > now+float64(d.config.Trust.MaxLifetimeSeconds) || !d.validEnrollmentWorkloadForms(actor) {
		return false
	}
	if !validCoownerLease(actor, check, p.Bounds.MaxIdentifierBytes) || !validCoownerAuthority(actor, p.Bounds.MaxIdentifierBytes) {
		return false
	}
	if actor.Mode != "apply" {
		return actor.PrincipalReference == nil
	}
	if !validEnrollmentTarget(actor, p.Bounds.MaxIdentifierBytes, now, float64(d.config.Trust.MaxLifetimeSeconds)) {
		return false
	}
	return domainEqual(actor.PrincipalReference.TargetGrantRevision, actor.Request.CoownerChange.ExpectedTargetGrantRevision)
}

func validCoownerLease(actor EnrollmentVerified, check EnrollmentCheck, maximum int) bool {
	if check.Phase == "admission" {
		return check.LeaseBinding == nil && actor.ReceiptBinding == nil
	}
	lease := check.LeaseBinding
	if lease == nil || enrollmentIdentifiers(maximum, lease.Epoch, lease.LeaseID, lease.Binding.RootID, lease.Binding.BindingRevision) != nil {
		return false
	}
	return lease.PrincipalID == actor.PrincipalID && lease.SessionID == actor.SessionID && lease.Scope == actor.Scope && lease.Binding.Scope == actor.Scope && lease.IntentFingerprint == actor.ExchangeFingerprint
}

func validCoownerAuthority(actor EnrollmentVerified, maximum int) bool {
	a, w := actor.CoownerAuthority, actor.EnrollmentCoownerWire
	if a == nil || w == nil || a.AccountKind != "organization" || a.TargetKind != "human" || !a.TargetAccepted || enrollmentIdentifiers(maximum, a.CommandRevision) != nil {
		return false
	}
	if !domainContains([]string{"confirmed", "revoking", "revoked"}, a.TargetNativeState) || !domainContains([]string{"active", "revoking", "revoked"}, a.ActorGrantState) {
		return false
	}
	if actor.Mode != "apply" {
		return validCoownerReceiptAuthority(actor)
	}
	if !coownerActorAuthorized(actor) || w.ReceiptActorPrincipalID != nil || w.ReceiptBinding != nil || w.ExchangeFingerprint != actor.RequestFingerprint {
		return false
	}
	if a.ActorGrantState != "active" && !(coownerSelfRevoke(actor) && a.ActorGrantState == "revoking") {
		return false
	}
	return actor.Request.Operation != EnrollmentCoownerGrant || a.TargetNativeState == "confirmed" && actor.PrincipalReference != nil && actor.PrincipalReference.TargetEligibility == "active"
}

func validCoownerReceiptAuthority(actor EnrollmentVerified) bool {
	w, a := actor.EnrollmentCoownerWire, actor.CoownerAuthority
	if !a.ReceiptAuthorized || w.ReceiptActorPrincipalID == nil || enrollmentIdentifiers(4096, *w.ReceiptActorPrincipalID) != nil {
		return false
	}
	if actor.PrincipalID == *w.ReceiptActorPrincipalID && actor.OwnerAuthorized {
		return false
	}
	if actor.PrincipalID != *w.ReceiptActorPrincipalID && (!actor.OwnerAuthorized || a.ActorGrantState != "active") {
		return false
	}
	if w.Mode == "receipt" {
		return coownerSelfRevoke(actor) && actor.Phase == "handoff" && w.ExchangeFingerprint == actor.RequestFingerprint && w.ReceiptBinding != nil && w.ReceiptBinding.CurrentStateDigest == nil
	}
	return w.Mode == "inspect" && w.ExchangeFingerprint == coownerInspectionFingerprint(actor.Request, *w.ReceiptActorPrincipalID) && (actor.Phase == "admission" && w.ReceiptBinding == nil || actor.Phase == "handoff" && w.ReceiptBinding != nil && w.ReceiptBinding.CurrentStateDigest != nil)
}

// The issuer binds this already-issued ticket once to the native-generated lease.
// No forest/d.mu lock is held over the callback and no recursive native validation occurs.
func (s *Server) precommitCoowner(d *domainEngine, entry *domainEntry, prepared stagedPreparation, permit *sourceWritePermit) error {
	if !enrollmentCoownerRequest(entry.enrollment.actor.Request) {
		return nil
	}
	actor, err := d.verifyEnrollment(context.Background(), entry.enrollment.input, "precommit", &entry.lease)
	if err != nil {
		return err
	}
	if err = d.retainCoownerPrecommit(entry, actor); err != nil {
		return err
	}
	if !permit.owns(s.sourceFence()) {
		return fmt.Errorf("co-owner source write permit lost")
	}
	s.forestMutex.RLock()
	defer s.forestMutex.RUnlock()
	scope := s.stagedScopes[entry.owned.Binding.ScopeID]
	if scope == nil || scope.pending != prepared.pending || prepared.pair.Key != entry.receiptKey {
		return fmt.Errorf("co-owner pending candidate changed")
	}
	if err = s.authorizeEnrollmentRootLocked(d, entry); err != nil {
		return err
	}
	if err = s.coownerPrecommitCandidateLocked(d, entry, prepared); err != nil {
		return err
	}
	return d.enrollmentLive(entry) // Recheck the stricter deadline after candidate/lock work, before writing.
}

func (d *domainEngine) retainCoownerPrecommit(entry *domainEntry, actor EnrollmentVerified) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	old := entry.enrollment.actor
	if !enrollmentActorSame(old, actor) || actor.ExpiresAt > old.ExpiresAt || old.ExpiresAt <= domainNow() {
		return fmt.Errorf("precommit co-owner authority changed/extended")
	}
	entry.enrollment.actor = actor // Atomically retain refreshed authority, including any shorter expiry.
	return d.enrollmentLiveLocked(entry)
}

func (s *Server) coownerPrecommitCandidateLocked(d *domainEngine, entry *domainEntry, prepared stagedPreparation) error {
	if prepared.pending != nil {
		root, err := s.forest.GetNode(entry.owned.Binding.RootID)
		if err != nil {
			return err
		}
		revision, err := stagedContentRevision(root)
		if err != nil || revision != entry.enrollment.actor.Request.ExpectedRevision {
			return fmt.Errorf("co-owner effect-boundary native CAS changed")
		}
		if err = coownerUnusedGeneration(root.CommandReceipts, entry.enrollment.actor.Request); err != nil {
			return err
		}
	}
	return s.validateCoownerPinsLocked(d, entry)
}

func coownerUnusedGeneration(history map[string]interface{}, request EnrollmentRequest) error {
	if request.Operation != EnrollmentCoownerGrant {
		return nil
	}
	for key, raw := range history {
		if !isStagedReceiptKey(key) {
			continue
		}
		var receipt stagedReceipt
		if err := decodeStagedInternal(raw, &receipt); err != nil {
			return err
		}
		if receipt.Command.Action != EnrollmentCoownerGrant {
			continue
		}
		record, err := decodeEnrollmentRecord(receipt.EnrollmentRecord, len(receipt.EnrollmentRecord))
		if err != nil {
			return err
		}
		if domainEqual(record.Request.TargetPrincipalID, request.TargetPrincipalID) && domainEqual(record.Request.CoownerChange.OwnerGrantRevision, request.CoownerChange.OwnerGrantRevision) {
			return fmt.Errorf("historical co-owner generation cannot be reused")
		}
	}
	return nil
}

// Rejection of a settled receipt replay is not an unknown write. An unresolved
// candidate or pre-existing source uncertainty still requires its actual witness.
func (s *Server) discardUnwrittenCoowner(d *domainEngine, entry *domainEntry, prepared stagedPreparation, permit *sourceWritePermit) bool {
	source := s.sourceFence()
	source.mu.Lock()
	clean := permit != nil && permit.coordinator == source && source.writer == permit && permit.active && !source.unknown
	source.mu.Unlock()
	if !clean || prepared.replayed && prepared.pending != nil {
		return false
	}
	s.forestMutex.Lock()
	scope := s.stagedScopes[entry.owned.Binding.ScopeID]
	if scope == nil || scope.pending != prepared.pending {
		s.forestMutex.Unlock()
		return false
	}
	scope.pending = nil
	s.forestMutex.Unlock()
	d.mu.Lock()
	entry.pendingKey = ""
	d.mu.Unlock()
	return true
}
