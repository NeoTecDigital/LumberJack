// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"math"
	"testing"
)

func TestEnrollmentSharedSessionFenceRequiresRealClosureAndStableRoots(t *testing.T) {
	f := newEnrollmentFixture(t)
	begin := f.enroll(t, f.input(EnrollmentProvision, "unit-session-account", "unit-session-create", "unit-session-proof", "absent", nil))
	f.received(t, begin)
	control := DomainControl{Action: "roots.snapshot", Epoch: begin.Lease.Epoch, HostID: f.config.HostID, ChannelToken: f.config.OwnerControlToken, PrincipalID: begin.Lease.PrincipalID, SessionID: begin.Lease.SessionID, ValidUntil: domainNow() + 20}
	result, err := f.server.DomainControl(context.Background(), control)
	if err != nil || len(result.Value.(EnrollmentRootSnapshot).Roots) == 0 {
		t.Fatal("actual root/session snapshot failed", err)
	}
	old := result.Value.(EnrollmentRootSnapshot)
	denied := f.input(EnrollmentProvision, "unit-other-account", "unit-other-create", "unit-fenced-proof", "absent", nil)
	if _, err = f.server.DomainEnroll(context.Background(), denied); err == nil {
		t.Fatal("shared session fence allowed a new org root")
	}
	enrollmentCloseSession(t, f, begin)
	if !enrollmentDiscard(t, f, begin).Completed {
		t.Fatal("actual adopted lease did not finish")
	}
	control.Action, control.RootSnapshot = "roots.recheck", &old
	if _, err = f.server.DomainControl(context.Background(), control); err == nil {
		t.Fatal("changed generation accepted stale root snapshot")
	}
	control.Action, control.RootSnapshot = "roots.snapshot", nil
	result, err = f.server.DomainControl(context.Background(), control)
	if err != nil {
		t.Fatal(err)
	}
	current := result.Value.(EnrollmentRootSnapshot)
	control.Action, control.RootSnapshot = "roots.recheck", &current
	if _, err = f.server.DomainControl(context.Background(), control); err != nil {
		t.Fatal("actual drained stable session roots denied", err)
	}
}

func enrollmentCloseSession(t *testing.T, f *enrollmentFixture, begin DomainBegin) {
	t.Helper()
	key := DomainGateKey{begin.Lease.PrincipalID, begin.Lease.SessionID, begin.Lease.Scope}
	control := DomainControl{Action: "close", Epoch: begin.Lease.Epoch, HostID: f.config.HostID, ChannelToken: f.config.OwnerControlToken, Keys: []DomainGateKey{key}}
	if _, err := f.server.DomainControl(context.Background(), control); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollmentStandaloneHelpersDoNotBroadenNamespaceOrLifetime(t *testing.T) {
	if domainFinite(math.NaN()) || domainFinite(math.Inf(1)) || domainFinite(math.Inf(-1)) || !domainFinite(1) {
		t.Fatal("nonfinite authority lifetime accepted")
	}
	if domainV2(DomainOwnedScope{}) || domainV2(DomainOwnedScope{Layout: DomainLayout{ContractRevision: "manifest-associates/0.1"}}) {
		t.Fatal("legacy scope silently promoted to /.2")
	}
	original := &DomainResolutionNamespace{PrincipalID: "unit-owner", SessionID: "unit-session", Scope: DomainScope{"unit-account", "manifest"}, RequestID: "unit-request", Purpose: "unit-purpose", RequestFingerprint: stagedHash(nil), GrantRevision: "unit-grant", AuthorityPolicyRevision: "unit-policy", CheckedAt: 1, ValidUntil: 2, OwnerAuthorized: true}
	current := *original
	current.CheckedAt, current.ValidUntil = 2, 3
	if !namespaceEqual(original, &current) {
		t.Fatal("refreshed timestamps changed immutable namespace")
	}
	current.OwnerAuthorized = false
	if namespaceEqual(original, &current) || namespaceEqual(original, nil) {
		t.Fatal("changed current ownership/null namespace accepted")
	}
}
