// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/core"
	"testing"
)

func TestNativeControlPrepareSealAndPureNegativeBindings(t *testing.T) {
	u := nativeControlUnitNew(t)
	ref := nativeUnitCapture(t, u, nil)
	input := nativeControlOpen{ref.ControlRef, u.f.actor.Evidence, "identity.mapping.prepare", "prepare-command", nil, stagedHash([]byte("original nonsecret command"))}
	got, err := u.f.p.openNativeControl(nativeUnitRequest(u, "control.open", input))
	if err != nil {
		t.Fatal(err)
	}
	var opened struct {
		LeaseRef ControlLeaseRef       `json:"leaseRef"`
		Snapshot NativeControlSnapshot `json:"snapshot"`
	}
	raw, _ := CanonicalDomainJSON(got)
	if sourceDecode(raw, &opened, u.f.config.Bounds) != nil {
		t.Fatal("closed control response mismatch")
	}
	s := opened.Snapshot
	expected := nativeVerifyExpected{"nativeControlSnapshot", s.Subject, s.RequestID, s.Purpose, s.CheckKey, nil, nil, domainNow()}
	if nativeUnitVerify(u, s, expected) != nil {
		t.Fatal("actual pure prepare seal refused")
	}
	expected.CheckKey.RawRequestSHA256 = stagedHash([]byte("wrong command"))
	if nativeUnitVerify(u, s, expected) == nil {
		t.Fatal("wrong raw body accepted")
	}
	expected.CheckKey = s.CheckKey
	expected.Now = s.ValidUntil
	if nativeUnitVerify(u, s, expected) == nil {
		t.Fatal("expiry renewed")
	}
	if _, err = u.f.p.releaseNativeControl(nativeUnitRequest(u, "control.release", nativeControlRelease{opened.LeaseRef, "released"})); err != nil {
		t.Fatal(err)
	}
}
func TestNativeControlPrecanonicalRealLeaseAndNullBranch(t *testing.T) {
	u := nativeControlUnitNew(t)
	receipt := nativeUnitConsent(t, u, "native-home", "mapping-home", "consent-home")
	input := precanonicalIdentityOpen{receipt.ConsentRef, u.f.actor.Evidence, "identity.association.establish", nil}
	got, err := u.f.p.openPrecanonicalIdentity(nativeUnitRequest(u, "identity.openPrecanonical", input))
	if err != nil {
		t.Fatal(err)
	}
	var opened struct {
		ControlLeaseRef ControlLeaseRef                 `json:"controlLeaseRef"`
		Proof           PrecanonicalAssociationEvidence `json:"proof"`
	}
	raw, _ := CanonicalDomainJSON(got)
	if sourceDecode(raw, &opened, u.f.config.Bounds) != nil {
		t.Fatal("precanonical closed shape mismatch")
	}
	proof := opened.Proof
	expected := nativeVerifyExpected{"precanonicalAssociationEvidence", u.f.actor.Evidence, u.f.actor.Evidence.RequestID, input.Purpose, proof.CheckKey, nil, nil, domainNow()}
	if nativeUnitVerify(u, proof, expected) != nil {
		t.Fatal("real preprincipal seal refused")
	}
	wrong := "invented-enrollment"
	expected.AssociationID = &wrong
	if nativeUnitVerify(u, proof, expected) == nil {
		t.Fatal("establish association null branch widened")
	}
	if opened.ControlLeaseRef.ControlSnapshotSHA256 != sourceCommandKey(proof.ControlSnapshot) || proof.CheckKey.RawRequestSHA256 != stagedHash(nativeUnitRequest(u, "identity.openPrecanonical", input).Payload) {
		t.Fatal("phase hashes conflated")
	}
	if _, err = u.f.p.releaseNativeControl(nativeUnitRequest(u, "control.release", nativeControlRelease{opened.ControlLeaseRef, "released"})); err != nil {
		t.Fatal(err)
	}
}
func nativeUnitBinding(t *testing.T, u *nativeControlUnit, rOwner SourceOwnerRef, revision string) sourceBindingResult {
	t.Helper()
	f := u.f
	original := sourceResolvedRequestBinding{"GET", "/workspace", stagedHash(nil)}
	resources := []SourceResourceRef{{"node", rOwner.RootID}}
	fields := []SourceFieldSet{{resources[0], sourceWorkspaceFields()}}
	intent := PersonalSourceIntent{"activation-personal-handoff/0.1", f.grant.Scope, rOwner, revision, "workspace.read", original.Method, original.FullTarget, original.BodySHA256, sourceCommandKey(original), resources, fields}
	got, err := f.p.bindingOpen(nativeUnitRequest(u, "binding.open", sourceBindingOpen{f.actor, f.grant, intent}))
	if err != nil {
		t.Fatal(err)
	}
	return got.(sourceBindingResult)
}
func TestNativeControlFreshSupabaseSessionDoesNotNeedNativeRelogin(t *testing.T) {
	u := nativeControlUnitNew(t)
	receipt := nativeUnitConsent(t, u, "native-home", "mapping-home", "consent-home")
	record := nativeUnitAttach(t, u, receipt)
	u.f.server.forest.ApplicationSessions = nil // Old native login genuinely gone.
	u.f.actor.SessionID = "fresh-supabase-session"
	u.f.actor.Evidence.SessionID = u.f.actor.SessionID
	opened := nativeUnitBinding(t, u, record.Binding.OwnerRef, record.Binding.BindingRevision)
	entry := u.f.p.entries[opened.LeaseRef.LeaseID]
	input := sourceBindingRecheck{opened.LeaseRef, u.f.actor, u.f.grant, *entry.intent}
	got, err := u.f.p.bindingRecheck(nativeUnitRequest(u, "binding.recheck", input))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := CanonicalDomainJSON(got)
	var wrapped sourceBindingResult
	if sourceDecode(raw, &wrapped, u.f.config.Bounds) != nil || !domainEqual(wrapped.LeaseRef, opened.LeaseRef) {
		t.Fatal("binding recheck wrapper altered lease")
	}
	expected := record.ConsentRevision
	key := MappingCheckKey{"consent-home", u.f.actor.Evidence.RequestID, entry.originalSHA, canonicalConsentDigest(record.Mapping, "consent-home", &expected), &expected, "current"}
	refRaw, _ := CanonicalDomainJSON(opened.LeaseRef)
	sealInput := mappingCurrentSeal{currentSealLease{"source", refRaw}, u.f.actor.Evidence, "identity.association.resolve", key, *record.Binding.AssociationID, record.Binding.Enrollment}
	seal, err := u.f.p.emitCurrentSeal(nativeUnitRequest(u, "mapping.currentSeal", sealInput))
	if err != nil {
		t.Fatal(err)
	}
	check := nativeVerifyExpected{"currentNativeConsent", u.f.actor.Evidence, key.RequestID, sealInput.Purpose, key, record.Binding.AssociationID, &record.Binding.Enrollment, domainNow()}
	if nativeUnitVerify(u, seal, check) != nil {
		t.Fatal("fresh current seal refused without native login")
	}
	consent := u.f.server.forest.PersonalBindings.Consents[record.ConsentRef]
	consent.State = "revoked"
	u.f.server.forest.PersonalBindings.Consents[record.ConsentRef] = consent
	if _, err = u.f.p.emitCurrentSeal(nativeUnitRequest(u, "mapping.currentSeal", sealInput)); err == nil {
		t.Fatal("revoked consent became authority")
	}
	_, _ = u.f.p.leaseRelease(context.Background(), nativeUnitRequest(u, "lease.release", sourceLeaseRelease{opened.LeaseRef, "released"}))
}
func TestNativeControlZeroRootSubjectFenceAndRealPendingInventory(t *testing.T) {
	u := nativeControlUnitNew(t)
	got, err := u.f.p.subjectRoots(nativeUnitRequest(u, "subjectRoots.snapshot", subjectRootsInput{u.f.actor.Evidence, nil}), false)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := got.(subjectRootsSnapshot)
	if len(snapshot.Roots) != 0 {
		t.Fatal("invented root")
	}
	captured := nativeUnitCapture(t, u, nil)
	input := nativeControlOpen{captured.ControlRef, u.f.actor.Evidence, "identity.mapping.prepare", "prepare-command", nil, stagedHash([]byte("original"))}
	if _, err = u.f.p.openNativeControl(nativeUnitRequest(u, "control.open", input)); err == nil {
		t.Fatal("zero-root fence bypassed")
	}
	raw, _ := CanonicalDomainJSON(snapshot)
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 6 {
		t.Fatal("subject snapshot shape widened")
	}
}
func TestNativeControlResourcesRecheckReturnsSameLeaseWrapper(t *testing.T) {
	u := nativeControlUnitNew(t)
	receipt := nativeUnitConsent(t, u, "native-home", "mapping-home", "consent-home")
	record := nativeUnitAttach(t, u, receipt)
	opened := nativeUnitBinding(t, u, record.Binding.OwnerRef, record.Binding.BindingRevision)
	entry := u.f.p.entries[opened.LeaseRef.LeaseID]
	input := sourceResourcesOpen{u.f.actor, u.f.grant, opened.Binding, *entry.intent, opened.LeaseRef}
	if _, err := u.f.p.resourcesOpen(nativeUnitRequest(u, "resources.open", input)); err != nil {
		t.Fatal(err)
	}
	got, err := u.f.p.resourcesRecheck(nativeUnitRequest(u, "resources.recheck", sourceBindingRecheck{opened.LeaseRef, u.f.actor, u.f.grant, *entry.intent}))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := CanonicalDomainJSON(got)
	var wrapped sourceResourcesResult
	if sourceDecode(raw, &wrapped, u.f.config.Bounds) != nil || !domainEqual(wrapped.LeaseRef, opened.LeaseRef) {
		t.Fatal("resource recheck missing same lease wrapper")
	}
	_, _ = u.f.p.leaseRelease(context.Background(), nativeUnitRequest(u, "lease.release", sourceLeaseRelease{opened.LeaseRef, "released"}))
}

func TestNativeControlExactOriginalPrimaryNewBinding(t *testing.T) {
	u := nativeControlUnitNew(t)
	candidate, _, _ := sourceUnitCommitted(t, u.f)
	receipt := candidate.candidate.Receipt
	opened := nativeUnitBinding(t, u, receipt.OwnerRef, receipt.BindingRevision)
	entry := u.f.p.entries[opened.LeaseRef.LeaseID]
	if opened.Binding.AssociationID != nil || opened.Binding.Enrollment.Enrollment.Mode != "new" {
		t.Fatal("NEW was relabeled EXISTING")
	}
	if _, err := u.f.p.bindingRecheck(nativeUnitRequest(u, "binding.recheck", sourceBindingRecheck{opened.LeaseRef, u.f.actor, u.f.grant, *entry.intent})); err != nil {
		t.Fatal(err)
	}
	ledger := u.f.server.forest.PersonalBindings
	saved := ledger.Receipts
	ledger.Receipts = map[string]core.PersonalProvisionRecord{}
	if _, err := u.f.p.bindingRecheck(nativeUnitRequest(u, "binding.recheck", sourceBindingRecheck{opened.LeaseRef, u.f.actor, u.f.grant, *entry.intent})); err == nil {
		t.Fatal("unpaired NEW accepted")
	}
	ledger.Receipts = saved
	_, _ = u.f.p.leaseRelease(context.Background(), nativeUnitRequest(u, "lease.release", sourceLeaseRelease{opened.LeaseRef, "released"}))
}
