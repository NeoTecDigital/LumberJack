// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"errors"
	"os"
	"testing"
)

func coownerInspectInput(original EnrollmentInput, actor, proof string) EnrollmentInput {
	return EnrollmentInput{ContractRevision: EnrollmentCoownerProofRevision, RequestID: "unit-request-" + proof, Proof: proof, Request: original.Request, Mode: "inspect", ReceiptActorPrincipalID: coownerString(actor)}
}

func coownerInspectResult(t *testing.T, f *enrollmentFixture, input EnrollmentInput) (DomainBegin, DomainReceived, coownerInspection) {
	t.Helper()
	begin := f.enroll(t, input)
	received := f.received(t, begin)
	var result coownerInspection
	if err := DecodeDomainJSON(received.Body, &result); err != nil {
		t.Fatal(err)
	}
	return begin, received, result
}

func coownerFinish(t *testing.T, f *enrollmentFixture, begin DomainBegin, proof string) DomainControl {
	t.Helper()
	control := DomainControl{Action: "handoff", Epoch: begin.Lease.Epoch, LeaseID: begin.Lease.LeaseID, HostID: f.config.HostID, ChannelToken: f.config.ControlToken, Proof: proof}
	validation := control
	validation.Action, validation.LeaseBinding, validation.PrincipalID, validation.SessionID = "enrollment.validate", &begin.Lease, begin.Lease.PrincipalID, begin.Lease.SessionID
	validation.RequestFingerprint, validation.ValidUntil = begin.Lease.IntentFingerprint, domainNow()+20
	if _, err := f.server.DomainControl(context.Background(), validation); err != nil {
		t.Fatal("receipt-only native lease validation denied", err)
	}
	result, err := f.server.DomainControl(context.Background(), control)
	if err != nil {
		t.Fatal(err)
	}
	permit := result.Value.(DomainPermit)
	control.Action, control.ResponseHash, control.Disposition, control.PermitID = "finish", begin.ResponseHash, "handed-off", permit.PermitID
	result, err = f.server.DomainControl(context.Background(), control)
	if err != nil || !result.Completed {
		t.Fatal("actual native terminal completion missing", err)
	}
	return control
}

func TestCoownerSelfRevokeFinishesOnlyExactOriginalExchange(t *testing.T) {
	f, root := newCoownerFixture(t)
	coownerFixtureGrant(t, f, root)
	f.coowner.principal, f.coowner.grant, f.targetRevision = "unit-added-owner", "unit-owner-generation-1", "unit-owner-generation-1"
	r := coownerFixtureInput(t, f, root, EnrollmentCoownerRevoke, "unit-self-remove", "unit-added-owner", f.targetRevision, "")
	begin := f.enroll(t, r)
	f.received(t, begin)
	f.targetState, f.coowner.grant = "revoked", "unit-revocation-tombstone"
	finish := coownerFinish(t, f, begin, "unit-self-receipt")
	check := f.coowner.checks[len(f.coowner.checks)-1]
	if check.Mode != "receipt" || check.ReceiptBinding == nil || check.ReceiptBinding.CurrentStateDigest != nil || *check.ReceiptActorPrincipalID != "unit-added-owner" || check.ExchangeFingerprint != begin.Lease.IntentFingerprint {
		t.Fatal("self-revoke did not use exact terminal receipt binding")
	}
	entry := f.server.domain.entries[begin.Lease.LeaseID]
	if entry.enrollment.actor.OwnerAuthorized || !entry.finished {
		t.Fatal("removed owner received ordinary authority or fake finish")
	}
	if err := f.server.AcknowledgeDomainCompletion(finish); err != nil {
		t.Fatal(err)
	}
	if f.server.domain.entries[begin.Lease.LeaseID] != nil {
		t.Fatal("original completion ACK did not retire original lease")
	}
	acl := coownerFixtureACL(t, f, root)
	if coownerGrantAllows(DomainVerified{Kind: "human", GrantRevision: "unit-owner-generation-1"}, acl.Coowners["unit-added-owner"], DomainAccess{Operation: "read", Fields: []string{"id"}}) {
		t.Fatal("revoked g1 remains usable")
	}
}

func TestCoownerInspectSeparatesActorEffectAndReadLeaseWithoutWriting(t *testing.T) {
	f, root := newCoownerFixture(t)
	original, applied := coownerFixtureGrant(t, f, root)
	f.coowner.principal, f.coowner.grant = "unit-added-owner", "unit-owner-generation-1"
	f.targetRevision = "unit-owner-generation-1"
	before := f.server.sourceForestRevision()
	f.server.stateWriter.write = func(stateSnapshot) error { t.Fatal("inspection attempted a source write"); return nil }
	input := coownerInspectInput(original, aclFixtureOwner, "unit-inspect-current-owner")
	begin, received, result := coownerInspectResult(t, f, input)
	if result.Outcome != "committed" || received.Pair == nil || result.PairDigest == nil || *result.PairDigest != coownerHash(received.Pair) {
		t.Fatal("inspection omitted actual paired witness")
	}
	if received.Pair.PrincipalID != aclFixtureOwner || received.Pair.RequestFingerprint != applied.Lease.IntentFingerprint || begin.Lease.PrincipalID != "unit-added-owner" || begin.Lease.IntentFingerprint != coownerInspectionFingerprint(original.Request, aclFixtureOwner) {
		t.Fatal("effect actor/E conflated with inspector/I")
	}
	if _, present := result.Receipt["status"]; present {
		t.Fatal("inspection manufactured applied/replayed status")
	}
	if result.CurrentState.State != "installed" || result.Completion.Effect != "settled" || result.Completion.OriginalExchange != "unproven" {
		t.Fatal("historical receipt became guessed original cleanup")
	}
	finish := coownerFinish(t, f, begin, "unit-inspect-handoff")
	if f.server.domain.entries[applied.Lease.LeaseID].finished || before != f.server.sourceForestRevision() {
		t.Fatal("inspection finished/mutated original effect")
	}
	if err := f.server.AcknowledgeDomainCompletion(finish); err != nil {
		t.Fatal(err)
	}
}

func TestCoownerUnknownRequiresActualPairRecoveryBeforeInspection(t *testing.T) {
	f, root := newCoownerFixture(t)
	actual := f.server.stateWriter.write
	f.server.stateWriter.write = func(snapshot stateSnapshot) error {
		if err := actual(snapshot); err != nil {
			return err
		}
		return errors.New("unit lost co-owner write ACK")
	}
	original := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-unknown-coowner", "unit-target", "", "unit-g1")
	begin := f.enroll(t, original)
	if f.received(t, begin).Pair != nil || !f.server.sourceFence().unknown {
		t.Fatal("unknown source write claimed success")
	}
	input := coownerInspectInput(original, aclFixtureOwner, "unit-inspect-unknown")
	_, received, result := coownerInspectResult(t, f, input)
	coownerAssertUnknown(t, received, result)
	f.server.stateWriter.write = actual
	if !enrollmentDiscard(t, f, begin).Completed || f.server.sourceFence().unknown {
		t.Fatal("actual pair reconciliation failed")
	}
	input.Proof, input.RequestID = "unit-inspect-settled", "unit-request-settled"
	_, received, result = coownerInspectResult(t, f, input)
	if received.Pair == nil || result.Outcome != "committed" || result.Completion.Effect != "settled" {
		t.Fatal("real settled pair unavailable after recovery")
	}
}

func coownerAssertUnknown(t *testing.T, received DomainReceived, result coownerInspection) {
	t.Helper()
	if result.Outcome != "unknown" || received.Pair != nil || result.Receipt != nil || result.PairDigest != nil || result.CurrentState != nil || result.Completion != nil {
		t.Fatal("unknown outcome leaked synthetic evidence")
	}
}

func TestCoownerMissingActualWitnessNeverBecomesReceiptSuccess(t *testing.T) {
	f, root := newCoownerFixture(t)
	original, _ := coownerFixtureGrant(t, f, root)
	if err := os.Remove(f.server.statePath()); err != nil {
		t.Fatal(err)
	}
	begin, received, result := coownerInspectResult(t, f, coownerInspectInput(original, aclFixtureOwner, "unit-inspect-missing"))
	coownerAssertUnknown(t, received, result)
	control := DomainControl{Action: "handoff", Epoch: begin.Lease.Epoch, LeaseID: begin.Lease.LeaseID, HostID: f.config.HostID, ChannelToken: f.config.ControlToken, Proof: "unit-missing-receipt-handoff"}
	if _, err := f.server.DomainControl(context.Background(), control); err == nil {
		t.Fatal("cache-only receipt issued a terminal delivery permit")
	}
}

func TestCoownerActualRestartPreservesFounderHistoryNotOldLeaseCompletion(t *testing.T) {
	f, root := newCoownerFixture(t)
	original, applied := coownerFixtureGrant(t, f, root)
	restarted := stagedTestServer(t, f.server.config.Process.DatabasePath)
	if err := restarted.loadFromFile(f.server.statePath()); err != nil {
		t.Fatal(err)
	}
	policy, _ := NewDomainOwnerPolicy(f.config.ACLMetadataKey)
	if err := restarted.ConfigureDomain(f.config, map[string]DomainProduct{"manifest": domainTestProduct{}}, policy); err != nil {
		t.Fatal(err)
	}
	f.server, f.session = restarted, "unit-coowner-restart-session"
	begin, received, result := coownerInspectResult(t, f, coownerInspectInput(original, aclFixtureOwner, "unit-inspect-restarted"))
	if result.Outcome != "committed" || received.Pair == nil || begin.Lease.Binding != applied.Lease.Binding || begin.Lease.Epoch == applied.Lease.Epoch || result.Completion.OriginalExchange != "unproven" {
		t.Fatal("restart fabricated prior epoch completion or replaced root")
	}
	node, _ := f.server.forest.GetNode(root)
	if node.CreatedBy != aclFixtureOwner || coownerFixtureACL(t, f, root).Coowners["unit-added-owner"].GrantRevision != "unit-owner-generation-1" {
		t.Fatal("restart lost bounded co-owner/founder state")
	}
}

func TestCoownerHistoricalGenerationCannotReplayOrReactivateAfterRegrant(t *testing.T) {
	f, root := newCoownerFixture(t)
	original, applied := coownerFixtureGrant(t, f, root)
	f.targetRevision = "unit-owner-generation-1"
	f.enroll(t, coownerFixtureInput(t, f, root, EnrollmentCoownerRevoke, "unit-revoke-g1", "unit-added-owner", f.targetRevision, ""))
	f.targetRevision = "unit-new-member-g0"
	f.enroll(t, coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-add-g2", "unit-added-owner", "unit-owner-generation-1", "unit-owner-generation-2"))
	before := f.server.sourceForestRevision()
	f.server.stateWriter.write = func(stateSnapshot) error { t.Fatal("historical replay attempted a paired write"); return nil }
	// Even an erroneously repeated original external g0 assertion cannot replace native g2.
	f.targetRevision = *original.Request.CoownerChange.ExpectedTargetGrantRevision
	original.Proof, original.RequestID = "unit-stale-replay", "unit-stale-replay-request"
	if begin, err := f.server.DomainEnroll(context.Background(), original); err == nil || err.Error() != "enrollment unavailable: installed co-owner pin removed/replaced" || begin.ExchangeID != "" {
		t.Fatal("stale historical grant replayed or current-generation denial lost", err)
	}
	if before != f.server.sourceForestRevision() || f.server.sourceFence().unknown || f.server.sourceFence().writer != nil {
		t.Fatal("stale replay rewrote effects or stranded clean source authority")
	}
	entry := f.server.domain.entries[f.coowner.leases[original.Proof].LeaseID]
	if entry == nil || !entry.finished || entry.pendingKey != "" || entry.pair != nil || entry.disposition != "irrevocably-discarded" {
		t.Fatal("settled historical rejection retained an unknown effect")
	}
	begin, received, result := coownerInspectResult(t, f, coownerInspectInput(original, aclFixtureOwner, "unit-inspect-superseded"))
	if received.Pair == nil || result.CurrentState == nil || result.CurrentState.State != "superseded" || result.CurrentState.OwnerGrantRevision == nil || *result.CurrentState.OwnerGrantRevision != "unit-owner-generation-2" {
		t.Fatal("historical g1 receipt became g2 entitlement")
	}
	if result.Completion == nil || result.Completion.OriginalExchange != "unproven" {
		t.Fatal("rejected replay fabricated original exchange completion")
	}
	finish := coownerFinish(t, f, begin, "unit-superseded-inspect-handoff")
	if err := f.server.AcknowledgeDomainCompletion(finish); err != nil {
		t.Fatal(err)
	}
	if f.server.domain.entries[begin.Lease.LeaseID] != nil || f.server.domain.entries[applied.Lease.LeaseID].finished || before != f.server.sourceForestRevision() {
		t.Fatal("inspection cleanup completed or rewrote the original exchange")
	}
}

func TestCoownerRejectedPendingReplayPreservesUnknownUntilActualRecovery(t *testing.T) {
	f, root := newCoownerFixture(t)
	actual, writes := f.server.stateWriter.write, 0
	f.server.stateWriter.write = func(snapshot stateSnapshot) error {
		writes++
		if err := actual(snapshot); err != nil {
			return err
		}
		return errors.New("unit lost original co-owner write ACK")
	}
	original := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-unknown-retry", "unit-added-owner", "", "unit-g1")
	begin := f.enroll(t, original)
	pending := f.server.stagedScopes[enrollmentScopeID(original.Request.Scope.AccountID)].pending
	if f.received(t, begin).Pair != nil || pending == nil || !f.server.sourceFence().unknown {
		t.Fatal("original unknown effect was not retained")
	}
	f.coowner.denyPrecommit = true
	retry := original
	retry.Proof, retry.RequestID = "unit-denied-pending-retry", "unit-denied-pending-request"
	retried := f.enroll(t, retry)
	if f.received(t, retried).Pair != nil || !f.server.sourceFence().unknown || f.server.stagedScopes[enrollmentScopeID(original.Request.Scope.AccountID)].pending != pending || writes != 1 {
		t.Fatal("rejected pending replay discarded unknown evidence or rewrote the pair")
	}
	f.server.stateWriter.write = actual
	if !enrollmentDiscard(t, f, begin).Completed || f.server.sourceFence().unknown {
		t.Fatal("actual original witness did not reconcile the unknown effect")
	}
	_, received, result := coownerInspectResult(t, f, coownerInspectInput(original, aclFixtureOwner, "unit-inspect-recovered-retry"))
	if received.Pair == nil || result.Outcome != "committed" || result.CurrentState == nil || result.CurrentState.State != "installed" {
		t.Fatal("rejected retry prevented witnessed inspection after actual recovery")
	}
}

func TestCoownerHistoricalGenerationCannotBeReusedByFreshCommand(t *testing.T) {
	f, root := newCoownerFixture(t)
	coownerFixtureGrant(t, f, root)
	f.targetRevision = "unit-owner-generation-1"
	f.enroll(t, coownerFixtureInput(t, f, root, EnrollmentCoownerRevoke, "unit-retire-g1", "unit-added-owner", f.targetRevision, ""))
	f.targetRevision = "unit-new-member-g0"
	f.enroll(t, coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-install-g2", "unit-added-owner", "unit-owner-generation-1", "unit-owner-generation-2"))
	f.targetRevision = "unit-owner-generation-2"
	f.enroll(t, coownerFixtureInput(t, f, root, EnrollmentCoownerRevoke, "unit-retire-g2", "unit-added-owner", f.targetRevision, ""))
	f.targetRevision = "unit-third-member-g0"
	input := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-reactivate-g1", "unit-added-owner", "unit-owner-generation-2", "unit-owner-generation-1")
	before := f.server.sourceForestRevision()
	f.server.stateWriter.write = func(stateSnapshot) error { t.Fatal("historical generation reuse attempted a paired write"); return nil }
	if _, err := f.server.DomainEnroll(context.Background(), input); err == nil || err.Error() != "enrollment unavailable: historical co-owner generation cannot be reused" {
		t.Fatal("fresh command reactivated a historical owner generation", err)
	}
	current := coownerFixtureACL(t, f, root).Coowners["unit-added-owner"]
	if current.State != "revoked" || current.GrantRevision != "unit-owner-generation-2" || before != f.server.sourceForestRevision() || f.server.sourceFence().unknown || f.server.stagedScopes[enrollmentScopeID(input.Request.Scope.AccountID)].pending != nil {
		t.Fatal("generation reuse changed the current tombstone or stranded an unwritten candidate")
	}
}
