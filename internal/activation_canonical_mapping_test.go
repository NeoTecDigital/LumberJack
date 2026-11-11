// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"net/http"
	"testing"
)

// Stub only Core verification/SQL responses; native control, crypto seals,
// writer permits, complete snapshots, real file commit and paired ledger are real.
func (u *nativeControlUnit) callback(w http.ResponseWriter, r *http.Request) {
	var e mappingCallbackEnvelope
	if json.NewDecoder(r.Body).Decode(&e) != nil || r.Header.Get("Authorization") != "Bearer "+u.config.MappingCallback.ChannelToken || u.deny {
		w.WriteHeader(403)
		return
	}
	result, err := u.callbackResult(e)
	if err != nil {
		w.WriteHeader(403)
		return
	}
	raw, _ := CanonicalDomainJSON(result)
	_ = json.NewEncoder(w).Encode(mappingCallbackResponse{e.ContractRevision, e.Issuer, e.Audience, e.HostID, e.Epoch, e.RequestID, e.Action, raw})
}
func (u *nativeControlUnit) callbackResult(e mappingCallbackEnvelope) (interface{}, error) {
	var p map[string]json.RawMessage
	if DecodeDomainJSON(e.Payload, &p) != nil {
		return nil, sourceInvalid()
	}
	if e.Action == "mapping.verifyCurrent" {
		return u.currentCallback(e, p)
	}
	var snapshot *NativeControlSnapshot
	_ = json.Unmarshal(p["nativeControlSnapshot"], &snapshot)
	if snapshot == nil {
		return nil, sourceDenied()
	}
	expected := nativeVerifyExpected{"nativeControlSnapshot", snapshot.Subject, e.RequestID, snapshot.Purpose, snapshot.CheckKey, nil, nil, domainNow()}
	if err := nativeUnitVerify(u, *snapshot, expected); err != nil {
		return nil, err
	}
	v := u.verified(snapshot.CheckKey, snapshot.Subject, "prepared")
	guard := mappingGuardRef{"unit-actual-worker", u.f.config.HostID, u.f.p.epoch, e.RequestID, snapshot.CheckKey.CommandID, snapshot.CheckKey.RawRequestSHA256, snapshot.CheckKey.StableCommandSHA256, v.ValidUntil}
	switch e.Action {
	case "mapping.open":
		return mappingGuard{guard, v}, nil
	case "mapping.check":
		return v, nil
	case "mapping.release":
		return mappingReleaseAck{guard.GuardRef, "completed", "committed", &v, domainNow(), &v.ValidUntil}, nil
	}
	return nil, sourceDenied()
}
func (u *nativeControlUnit) verified(k MappingCheckKey, s SourceSubjectEvidence, stage string) verifiedCanonicalMapping {
	purpose := "identity.association.consent"
	if stage == "current" {
		purpose = "identity.mapping.current"
	}
	state := CanonicalState{}
	if stage == "current" {
		rev := "unit-real-sql-revision"
		b := u.mapping.Binding
		state = CanonicalState{PrincipalRegistered: true, AccountRegistryRevision: &rev, PersonalGrant: &core.PersonalMappedGrant{PrincipalID: b.PrincipalID,
			Scope: core.PersonalGrantScope{AccountID: b.Account.AccountID, Product: "momentum"}, Account: b.Account,
			Capabilities: []string{"identity.read"}, Revision: "unit-base-current", State: "active"}}
	}
	now := domainNow()
	until := min(s.ValidUntil, now+5)
	if u.expired {
		until = now - 1
	}
	return verifiedCanonicalMapping{stage, u.mapping, state, s, k.RequestID, purpose, k.RawRequestSHA256, k.StableCommandSHA256, now, until, CanonicalMappingRevision}
}
func (u *nativeControlUnit) currentCallback(e mappingCallbackEnvelope, p map[string]json.RawMessage) (interface{}, error) {
	var current CurrentNativeConsent
	var subject SourceSubjectEvidence
	var association string
	var enrollment SourceEnrollment
	_ = json.Unmarshal(p["currentNativeConsent"], &current)
	_ = json.Unmarshal(p["subject"], &subject)
	_ = json.Unmarshal(p["associationId"], &association)
	_ = json.Unmarshal(p["enrollmentRef"], &enrollment)
	expected := nativeVerifyExpected{"currentNativeConsent", subject, e.RequestID, current.Evidence.Purpose, current.CheckKey, &association, &enrollment, domainNow()}
	if err := nativeUnitVerify(u, current, expected); err != nil {
		return nil, err
	}
	return u.verified(current.CheckKey, subject, "current"), nil
}
func nativeUnitMapping(u *nativeControlUnit, root, id string) CanonicalResolvedMapping {
	f := u.f
	m := CanonicalResolvedMapping{MappingID: id, MappingRevision: "mapping-1", ReservationID: "human-reservation", ReservationRevision: "reservation-1", Issuer: f.actor.Evidence.Issuer, Subject: f.actor.Evidence.Subject, Binding: core.PersonalNativeBinding{PrincipalID: f.actor.PrincipalID, Account: f.grant.Account, OwnerRef: SourceOwnerRef{RuntimeID: f.server.forest.ID, RootID: root, OwnerID: "native-owner"}}, NativeAuthorityRef: f.config.SourceAuthorityRef, SourcePolicyRevision: f.config.SourcePolicyRevision}
	raw, _ := CanonicalDomainJSON(m)
	var fields map[string]json.RawMessage
	_ = DecodeDomainJSON(raw, &fields)
	delete(fields, "resolvedMappingSha256")
	m.ResolvedMappingSHA256 = sourceCommandKey(fields)
	return m
}
func nativeUnitConsent(t *testing.T, u *nativeControlUnit, root, id, command string) sourceConsentReceipt {
	t.Helper()
	u.mapping = nativeUnitMapping(u, root, id)
	ref := nativeUnitCapture(t, u, &root)
	input := canonicalConsentInput{command, ref.ControlRef, u.f.actor.Evidence, "unit-prepared-mapping", root, "native-owner", nil, u.mapping}
	got, err := u.f.p.establishCanonicalConsent(context.Background(), nativeUnitRequest(u, "consent.establish", input))
	if err != nil {
		t.Fatal(err)
	}
	return got.(sourceConsentReceipt)
}
func nativeUnitAssociation(u *nativeControlUnit, receipt sourceConsentReceipt, id string) SourceAssociationRecord {
	m := u.mapping
	return SourceAssociationRecord{AssociationID: id, Issuer: m.Issuer, Subject: m.Subject, Binding: SourceNativeBinding{m.Binding.PrincipalID, m.Binding.Account, m.Binding.OwnerRef}, Revision: "unit-association-revision", State: "active", NativeAuthorityRef: m.NativeAuthorityRef, SourcePolicyRevision: m.SourcePolicyRevision, SourceRevision: receipt.SourceRevision, ConsentRef: receipt.ConsentRef, ConsentRevision: receipt.ConsentRevision}
}
func nativeUnitAttach(t *testing.T, u *nativeControlUnit, receipt sourceConsentReceipt) core.PersonalMappingRecord {
	t.Helper()
	record := nativeUnitAssociation(u, receipt, "unit-association-"+u.mapping.MappingID)
	association := record.AssociationID
	// Original EXISTING enrollment ACK is a synthetic SQL fixture, not native authority.
	enrollment := SourceEnrollment{CommandID: "unit-existing-enrollment", Revision: "unit-enrollment-revision", Enrollment: core.PersonalEnrollmentSpec{Mode: "existing", ExistingIdentityRef: &association}}
	input := canonicalAttachInput{"unit-current-worker", u.f.actor.Evidence, record, enrollment, "unit-attach-" + u.mapping.MappingID, nil}
	if _, err := u.f.p.attachCanonicalMapping(context.Background(), nativeUnitRequest(u, "mapping.attach", input)); err != nil {
		t.Fatal(err)
	}
	return u.f.server.forest.PersonalBindings.Mappings[u.mapping.MappingID]
}
func TestNativeCanonicalDurableConsentAttachAndMultipleRoots(t *testing.T) {
	u := nativeControlUnitNew(t)
	u.f.server.forest.Children["native-home"].CommandReceipts["legacy-unknown"] = stagedTestUnknown()
	receipt := nativeUnitConsent(t, u, "native-home", "mapping-home", "consent-home")
	first := nativeUnitAttach(t, u, receipt)
	nativeUnitRoot(t, u, "native-other")
	receipt = nativeUnitConsent(t, u, "native-other", "mapping-other", "consent-other")
	second := nativeUnitAttach(t, u, receipt)
	disk := stagedTestDisk(t, u.f.server)
	if len(disk.PersonalBindings.Mappings) != 2 || disk.Children[first.Mapping.Binding.OwnerRef.RootID].ID == disk.Children[second.Mapping.Binding.OwnerRef.RootID].ID {
		t.Fatal("multi-root human collapsed")
	}
	if !domainEqual(disk.Children["native-home"].CommandReceipts["legacy-unknown"], stagedTestUnknown()) || len(disk.Children["native-home"].Users) != 1 {
		t.Fatal("legacy receipt or real ACL dropped")
	}
	if !domainEqual(disk.Children["native-home"].Metadata["source_unknown"], stagedTestUnknown()) {
		t.Fatal("unknown source bag changed")
	}
	for _, scope := range u.f.server.stagedScopes {
		if u.f.server.validateCanonicalStagedDescriptorLocked(scope.descriptor) != nil {
			t.Fatal("actual durable profile recovery denied")
		}
	}
	roots, err := u.f.p.actualPersonalRoots(enrollmentSessionKey{u.f.actor.PrincipalID, u.f.actor.SessionID})
	if err != nil || len(roots) != 2 {
		t.Fatal("mapped roots absent from drain")
	}
}
func TestNativeCanonicalSameCommandRetryAndConflict(t *testing.T) {
	u := nativeControlUnitNew(t)
	root := "native-home"
	u.mapping = nativeUnitMapping(u, root, "mapping-home")
	ref := nativeUnitCapture(t, u, &root)
	input := canonicalConsentInput{"consent-home", ref.ControlRef, u.f.actor.Evidence, "unit-prepared-mapping", root, "native-owner", nil, u.mapping}
	r := nativeUnitRequest(u, "consent.establish", input)
	first, err := u.f.p.establishCanonicalConsent(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := u.f.p.establishCanonicalConsent(context.Background(), r)
	if err != nil || !domainEqual(first, second) {
		t.Fatal("retry reallocated or lost receipt")
	}
	expected := "wrong-CAS"
	input.ExpectedConsentRevision = &expected
	if _, err = u.f.p.establishCanonicalConsent(context.Background(), nativeUnitRequest(u, "consent.establish", input)); err == nil {
		t.Fatal("same command changed input accepted")
	}
}
func TestNativeCanonicalUnknownUsesActualFileWitnessAndCleanupACK(t *testing.T) {
	u := nativeControlUnitNew(t)
	root := "native-home"
	u.mapping = nativeUnitMapping(u, root, "mapping-home")
	ref := nativeUnitCapture(t, u, &root)
	actual := u.f.server.stateWriter.write
	u.f.server.stateWriter.write = func(s stateSnapshot) error {
		if err := actual(s); err != nil {
			return err
		}
		return errors.New("unit unknown durable ACK")
	}
	i := canonicalConsentInput{"consent-home", ref.ControlRef, u.f.actor.Evidence, "unit-prepared-mapping", root, "native-owner", nil, u.mapping}
	if _, err := u.f.p.establishCanonicalConsent(context.Background(), nativeUnitRequest(u, "consent.establish", i)); err == nil {
		t.Fatal("unknown reported success")
	}
	e := nativeUnitUnknown(t, u)
	if u.f.p.recoverCanonicalWitness(context.Background(), e) == nil || !e.unknown {
		t.Fatal("file pair substituted for Core cleanup")
	}
	if u.f.server.forest.PersonalBindings == nil {
		t.Fatal("real file witness not factually published")
	}
	if _, err := u.f.p.coordinator.beginRead(nil); err == nil {
		t.Fatal("unknown produced fresh authority")
	}
}
func nativeUnitUnknown(t *testing.T, u *nativeControlUnit) *canonicalSourceEntry {
	t.Helper()
	for _, s := range u.f.p.entries {
		if s.canonical != nil && s.canonical.unknown {
			return s.canonical
		}
	}
	t.Fatal("unknown actual entry missing")
	return nil
}
