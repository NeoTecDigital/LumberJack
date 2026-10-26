// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"testing"
)

func TestEnrollmentProvisionRealPairAndAccountIsolation(t *testing.T) {
	f := newEnrollmentFixture(t)
	before, _ := CanonicalDomainJSON(stagedTestRecord(t, f.server.forest).Metadata)
	a := f.enroll(t, f.input(EnrollmentProvision, "unit-png-account", "unit-create-a", "unit-proof-a", "absent", nil))
	b := f.enroll(t, f.input(EnrollmentProvision, "unit-other-account", "unit-create-b", "unit-proof-b", "absent", nil))
	if a.Lease.Binding.RootID == b.Lease.Binding.RootID || a.Lease.Binding.RootID == a.Lease.Scope.AccountID {
		t.Fatal("canonical accounts/native roots collapsed")
	}
	enrollmentAssertAppliedPair(t, f.received(t, a), a, "applied")
	enrollmentAssertAppliedPair(t, f.received(t, b), b, "applied")
	disk := stagedTestDisk(t, f.server)
	after, _ := CanonicalDomainJSON(stagedTestRecord(t, disk).Metadata)
	if string(before) != string(after) {
		t.Fatal("unrelated source metadata/numbers changed")
	}
	for _, begin := range []DomainBegin{a, b} {
		enrollmentAssertRoot(t, f, begin)
	}
}

func enrollmentAssertAppliedPair(t *testing.T, received DomainReceived, begin DomainBegin, status string) {
	t.Helper()
	if received.Pair == nil || received.Pair.Sequence == 0 || received.Pair.SnapshotHash == "" || received.Pair.RequestFingerprint != begin.Lease.IntentFingerprint || received.Pair.Binding != begin.Lease.Binding || received.ResponseHash != stagedHash(received.Body) {
		t.Fatal("body/cache replaced actual paired native witness")
	}
	var envelope map[string]interface{}
	if err := DecodeDomainJSON(received.Body, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["receipt"].(map[string]interface{})["status"] != status {
		t.Fatal("unexpected real paired receipt status")
	}
}

func enrollmentAssertRoot(t *testing.T, f *enrollmentFixture, begin DomainBegin) {
	t.Helper()
	scope := f.server.stagedScopes[enrollmentScopeID(begin.Lease.Scope.AccountID)]
	index, err := stagedForestIndex(stagedTestDisk(t, f.server))
	if err != nil {
		t.Fatal(err)
	}
	account, root := index[scope.descriptor.Binding.AccountRootID], index[begin.Lease.Binding.RootID]
	if account == nil || root == nil || account.Kind != "formalentity" || account.ID == begin.Lease.Scope.AccountID || account.ID == root.ID || root.Metadata["accountId"] != begin.Lease.Scope.AccountID || len(account.Children) != 1 {
		t.Fatal("formalentity/account/business-root isolation broken")
	}
}

func TestEnrollmentExactReplayAllowsFreshSessionNotChangedClaim(t *testing.T) {
	f := newEnrollmentFixture(t)
	first := f.enroll(t, f.input(EnrollmentProvision, "unit-replay-account", "unit-stable-command", "unit-original-proof", "absent", nil))
	f.mu.Lock()
	f.session = "unit-fresh-verified-session"
	f.mu.Unlock()
	input := f.input(EnrollmentProvision, "unit-replay-account", "unit-stable-command", "unit-fresh-proof", "absent", nil)
	replay := f.enroll(t, input)
	if replay.Lease.Binding != first.Lease.Binding || replay.Lease.SessionID == first.Lease.SessionID {
		t.Fatal("fresh admission allocated a different pending account or revived old session")
	}
	enrollmentAssertAppliedPair(t, f.received(t, replay), replay, "replayed")
	f.mu.Lock()
	f.claim = "unit-replaced-owner-claim"
	f.mu.Unlock()
	input.Proof, input.RequestID = "unit-replaced-claim-proof", "unit-replaced-request"
	if _, err := f.server.DomainEnroll(context.Background(), input); err == nil {
		t.Fatal("replaced original owner claim replayed")
	}
	if len(f.server.domain.scopes) != 1 {
		t.Fatal("replay invented additional account roots")
	}
}

func TestEnrollmentOpaqueAcceptedActorGrantRevokeAndRevisionPins(t *testing.T) {
	f := newEnrollmentFixture(t)
	provision := f.enroll(t, f.input(EnrollmentProvision, "unit-org-account", "unit-create", "unit-create-proof", "absent", nil))
	rootID := provision.Lease.Binding.RootID
	target := "unit-opaque-associate-channel-actor"
	grant := f.enroll(t, f.input(EnrollmentReadGrant, "unit-org-account", "unit-grant", "unit-grant-proof", enrollmentCurrentRevision(t, f, rootID), &target))
	enrollmentAssertAppliedPair(t, f.received(t, grant), grant, "applied")
	root, _ := f.server.forest.GetNode(rootID)
	policy := &domainOwnerPolicy{key: f.config.ACLMetadataKey}
	acl, err := policy.acl(DomainRecord{ID: rootID, Metadata: root.Metadata})
	if err != nil || acl.Principals[target]["read"].TargetGrantRevision != f.targetRevision {
		t.Fatal("explicit opaque actor permission revision not pinned", err)
	}
	f.mu.Lock()
	f.targetState = "revoked"
	f.mu.Unlock()
	revoke := f.enroll(t, f.input(EnrollmentReadRevoke, "unit-org-account", "unit-revoke", "unit-revoke-proof", enrollmentCurrentRevision(t, f, rootID), &target))
	enrollmentAssertAppliedPair(t, f.received(t, revoke), revoke, "applied")
	root, _ = f.server.forest.GetNode(rootID)
	acl, err = policy.acl(DomainRecord{ID: rootID, Metadata: root.Metadata})
	if err != nil || len(acl.Principals[target]) != 0 {
		t.Fatal("authoritative revoke retained target read authority", err)
	}
}

func enrollmentCurrentRevision(t *testing.T, f *enrollmentFixture, rootID string) string {
	t.Helper()
	root, err := f.server.forest.GetNode(rootID)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := stagedContentRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func TestEnrollmentTargetGrantReplacementInvalidatesOriginalReplay(t *testing.T) {
	f := newEnrollmentFixture(t)
	created := f.enroll(t, f.input(EnrollmentProvision, "unit-target-replay", "unit-create", "unit-proof-create", "absent", nil))
	target := "unit-member"
	input := f.input(EnrollmentReadGrant, "unit-target-replay", "unit-actor-grant", "unit-proof-grant", enrollmentCurrentRevision(t, f, created.Lease.Binding.RootID), &target)
	f.enroll(t, input)
	f.mu.Lock()
	f.targetRevision = "unit-replaced-target-revision"
	f.mu.Unlock()
	input.Proof, input.RequestID = "unit-proof-target-replaced", "unit-replacement-request"
	if _, err := f.server.DomainEnroll(context.Background(), input); err == nil {
		t.Fatal("revoked/replaced original target BASE revision replayed")
	}
}
