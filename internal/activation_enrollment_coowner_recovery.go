// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"fmt"
	"math"
)

func (s *Server) handoffCoownerReceipt(ctx context.Context, d *domainEngine, entry *domainEntry, input DomainControl) (DomainControlResult, error) {
	check, old, err := coownerReceiptCheck(d, entry, input.Proof)
	if err != nil {
		return DomainControlResult{}, err
	}
	permit, err := s.sourceFence().beginRead(nil)
	if err != nil {
		return DomainControlResult{}, err
	}
	defer permit.release()
	if err = s.coownerReceiptCurrent(ctx, d, entry); err != nil {
		return DomainControlResult{}, err
	}
	actor, err := d.verifyEnrollment(ctx, check, "handoff", &entry.lease)
	if err != nil {
		return DomainControlResult{}, err
	}
	if actor.PrincipalID != old.PrincipalID || actor.SessionID != old.SessionID || actor.Scope != old.Scope || actor.Issuer != old.Issuer || old.ExpiresAt <= domainNow() {
		return DomainControlResult{}, fmt.Errorf("receipt-only live identity changed/expired")
	}
	d.mu.Lock()
	actor.ExpiresAt = math.Min(actor.ExpiresAt, old.ExpiresAt)
	entry.enrollment.actor = actor
	d.mu.Unlock()
	if err = s.coownerReceiptCurrent(ctx, d, entry); err != nil {
		return DomainControlResult{}, err
	}
	if err = permit.recheck(); err != nil {
		return DomainControlResult{}, err
	}
	return coownerReceiptPermit(d, entry)
}

func coownerReceiptCheck(d *domainEngine, entry *domainEntry, proof string) (EnrollmentInput, EnrollmentVerified, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	old := entry.enrollment.actor
	if !d.activeLocked(entry) || entry.pendingKey != "" || entry.pair == nil || !enrollmentCoownerRequest(old.Request) {
		return EnrollmentInput{}, old, fmt.Errorf("actual settled co-owner receipt required")
	}
	check := entry.enrollment.input
	check.Proof = proof
	pair := *entry.pair
	check.ReceiptBinding = &EnrollmentCoownerReceiptBinding{Pair: pair, ResponseHash: entry.responseHash}
	if check.Mode == "inspect" {
		view := entry.enrollment.inspection
		if view == nil || view.Outcome != "committed" || view.CurrentState == nil {
			return check, old, fmt.Errorf("unknown inspection cannot issue a delivery permit")
		}
		digest := coownerHash(view.CurrentState)
		check.ReceiptBinding.CurrentStateDigest = &digest
		return check, old, nil
	}
	if !coownerSelfRevoke(old) || old.PrincipalID == old.Request.CoownerChange.FounderPrincipalID {
		return check, old, fmt.Errorf("only original non-founder self-revoke uses terminal receipt mode")
	}
	check.Mode = "receipt"
	principal := old.PrincipalID
	check.ReceiptActorPrincipalID = &principal
	return check, old, nil
}

func (s *Server) coownerReceiptCurrent(ctx context.Context, d *domainEngine, entry *domainEntry) error {
	if entry.enrollment.input.Mode == "inspect" {
		observed, pair, err := s.observeCoowner(ctx, d, entry)
		if err != nil {
			return err
		}
		if pair == nil || coownerHash(observed) != entry.responseHash || !domainEqual(pair, entry.pair) {
			return fmt.Errorf("co-owner observation changed; fresh inspection required")
		}
		return nil
	}
	s.forestMutex.RLock()
	observation, err := s.coownerObservationLocked(d, entry, entry.lease.PrincipalID)
	if err == nil {
		err = s.validateCoownerPinsLocked(d, entry)
	}
	s.forestMutex.RUnlock()
	if err != nil {
		return err
	}
	pair := entry.pair
	if pair == nil || pair.ReceiptKey != observation.pair.Key || pair.NativeFingerprint != observation.pair.Fingerprint || pair.ReceiptHash != observation.pair.ReceiptHash || pair.Revision != observation.pair.AfterRevision {
		return fmt.Errorf("original self-revoke receipt replaced")
	}
	witness, err := s.inspectEnrollmentPair(ctx, observation.snapshot, observation.pair, entry.owned.Bounds.MaxSnapshotBytes)
	if err != nil {
		return err
	}
	defer witness.close()
	if !witness.current() {
		return fmt.Errorf("self-revoke witness changed")
	}
	return nil
}

func coownerReceiptPermit(d *domainEngine, entry *domainEntry) (DomainControlResult, error) {
	id, err := newDomainID()
	if err != nil {
		return DomainControlResult{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.activeLocked(entry) || d.enrollmentLiveLocked(entry) != nil || entry.pendingKey != "" || entry.pair == nil {
		return DomainControlResult{}, fmt.Errorf("receipt exchange no longer active")
	}
	entry.permitID = id
	return DomainControlResult{Value: DomainPermit{d.epoch, entry.lease.LeaseID, id, entry.responseHash}}, nil
}
