// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"testing"
)

func TestEnrollmentCurrentCallbackRejectsUntrustedAuthority(t *testing.T) {
	for _, corruption := range []string{"issuer", "kind", "owner", "expired", "proof", "extra", "missing", "purpose", "target"} {
		t.Run(corruption, func(t *testing.T) { enrollmentRejectCorruptedActor(t, corruption) })
	}
}

func enrollmentRejectCorruptedActor(t *testing.T, corruption string) {
	t.Helper()
	f := newEnrollmentFixture(t)
	input := f.input(EnrollmentProvision, "unit-denied-account", "unit-denied-command", "unit-denied-proof", "absent", nil)
	if corruption == "target" {
		created := f.enroll(t, f.input(EnrollmentProvision, "unit-denied-account", "unit-create", "unit-create-proof", "absent", nil))
		target := "unit-registered-channel-actor"
		input = f.input(EnrollmentReadGrant, "unit-denied-account", "unit-grant", "unit-denied-proof", enrollmentCurrentRevision(t, f, created.Lease.Binding.RootID), &target)
	}
	f.mu.Lock()
	f.corrupt = corruption
	f.mu.Unlock()
	before := f.server.sourceForestRevision()
	if _, err := f.server.DomainEnroll(context.Background(), input); err == nil {
		t.Fatal("untrusted/expired/unmapped callback authority accepted")
	}
	if before != f.server.sourceForestRevision() {
		t.Fatal("denied authority changed native source")
	}
}

func TestEnrollmentCurrentProofSingleUseAndCASConflictNoEffect(t *testing.T) {
	f := newEnrollmentFixture(t)
	input := f.input(EnrollmentProvision, "unit-cas-account", "unit-original", "unit-single-use", "absent", nil)
	f.enroll(t, input)
	before := f.server.sourceForestRevision()
	if _, err := f.server.DomainEnroll(context.Background(), input); err == nil {
		t.Fatal("callback single-use proof replay accepted")
	}
	target := "unit-target"
	stale := f.input(EnrollmentReadGrant, "unit-cas-account", "unit-stale-command", "unit-stale-proof", "lj.owned/v1:"+stagedHash([]byte("stale")), &target)
	if _, err := f.server.DomainEnroll(context.Background(), stale); err == nil {
		t.Fatal("stale expected revision applied")
	}
	if before != f.server.sourceForestRevision() {
		t.Fatal("refused CAS/proof changed graph")
	}
}

func TestEnrollmentHandoffFreshCallbackKeepsOriginalClaimAndDeadline(t *testing.T) {
	f := newEnrollmentFixture(t)
	begin := f.enroll(t, f.input(EnrollmentProvision, "unit-handoff-account", "unit-handoff-command", "unit-admission", "absent", nil))
	f.received(t, begin)
	entry := f.server.domain.entries[begin.Lease.LeaseID]
	originalDeadline := entry.enrollment.actor.ExpiresAt
	control := DomainControl{Action: "handoff", Epoch: begin.Lease.Epoch, LeaseID: begin.Lease.LeaseID, HostID: f.config.HostID, ChannelToken: f.config.ControlToken, Proof: "unit-handoff-current"}
	result, err := f.server.DomainControl(context.Background(), control)
	if err != nil || result.Value.(DomainPermit).ResponseHash != begin.ResponseHash || entry.enrollment.actor.ExpiresAt > originalDeadline {
		t.Fatal("fresh handoff failed/extended original expiry", err)
	}
	f.mu.Lock()
	f.claim = "unit-claim-reissued-mid-lease"
	f.mu.Unlock()
	control.Proof = "unit-handoff-replaced-claim"
	if _, err = f.server.DomainControl(context.Background(), control); err == nil {
		t.Fatal("mid-lease claim replacement authorized handoff")
	}
}

func TestEnrollmentUnknownTargetAndOwnerCannotReceiveMemberReadGrant(t *testing.T) {
	for _, state := range []string{"pending", "revoked", "unknown", "owner"} {
		t.Run(state, func(t *testing.T) { enrollmentRejectIneligibleTarget(t, state) })
	}
}

func enrollmentRejectIneligibleTarget(t *testing.T, state string) {
	t.Helper()
	f := newEnrollmentFixture(t)
	created := f.enroll(t, f.input(EnrollmentProvision, "unit-target-account", "unit-create", "unit-create-proof", "absent", nil))
	target := "unit-registered-but-ineligible"
	f.mu.Lock()
	f.targetState = state
	if state == "owner" {
		f.targetState, target = "active", "unit-verified-momentum-human"
	}
	f.mu.Unlock()
	before := f.server.sourceForestRevision()
	input := f.input(EnrollmentReadGrant, "unit-target-account", "unit-grant", "unit-target-proof", enrollmentCurrentRevision(t, f, created.Lease.Binding.RootID), &target)
	if _, err := f.server.DomainEnroll(context.Background(), input); err == nil || before != f.server.sourceForestRevision() {
		t.Fatal("unaccepted access/owner received member read ACL")
	}
}
