// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"strings"
	"testing"
)

func wlAdministrationFixture(t *testing.T) (*enrollmentFixture, EnrollmentInput, string) {
	t.Helper()
	f := administrationFixtureOver(t, newWorkloadFixture(t))
	input := administrationInput(f, "admin_wl_proof")
	root := input.Request.Administration.Grants["root"]
	root[nativeStoreCommand] = domainGrant{Fields: []string{"id"}, CreateKinds: []string{"png_record"}}
	first := f.enroll(t, input)
	enrollmentAssertAppliedPair(t, f.received(t, first), first, "applied")
	return f, input, first.Lease.Binding.RootID
}

func wlAdministrationControl(f *enrollmentFixture, input EnrollmentInput, operation, rootRevision, tag string) EnrollmentInput {
	target := wlPrincipal
	control := input
	request := input.Request
	request.Operation, request.TargetPrincipalID, request.ExpectedRevision, request.CommandID = operation, &target, rootRevision, "unit-admin-"+tag
	control.Request, control.Proof, control.RequestID = request, "admin_"+strings.ReplaceAll(tag, "-", "_"), "admin_request_"+tag
	return control
}

func TestAdministratorMayGrantAndRevokeAWorkload(t *testing.T) {
	f, input, rootID := wlAdministrationFixture(t)
	grant := f.enroll(t, wlAdministrationControl(f, input, EnrollmentWorkloadGrant, enrollmentCurrentRevision(t, f, rootID), "grant"))
	enrollmentAssertAppliedPair(t, f.received(t, grant), grant, "applied")
	receipt := aclFixtureReceipt(t, f, grant)
	if receipt.Command.PrincipalID != "unit-verified-momentum-human" || receipt.Command.Action != EnrollmentWorkloadGrant {
		t.Fatalf("administrator grant attribution %+v", receipt.Command)
	}
	if _, listed := wlRootACL(t, f, rootID).Principals[wlPrincipal]; !listed {
		t.Fatal("the administrator's grant did not land")
	}
	f.mu.Lock()
	f.targetState = "revoked"
	f.mu.Unlock()
	revoke := f.enroll(t, wlAdministrationControl(f, input, EnrollmentWorkloadRevoke, enrollmentCurrentRevision(t, f, rootID), "revoke"))
	enrollmentAssertAppliedPair(t, f.received(t, revoke), revoke, "applied")
	if _, listed := wlRootACL(t, f, rootID).Principals[wlPrincipal]; listed {
		t.Fatal("the administrator's revoke did not land")
	}
}

// The administrator's control is only the workload's. It has never been able to change a member's read.
func TestAdministratorControlStopsAtWorkloads(t *testing.T) {
	f, input, rootID := wlAdministrationFixture(t)
	control := wlAdministrationControl(f, input, EnrollmentReadGrant, enrollmentCurrentRevision(t, f, rootID), "member")
	if _, err := f.server.DomainEnroll(contextBackground(), control); err == nil {
		t.Fatal("an administrator changed a member's read")
	}
	replaced := wlAdministrationControl(f, input, EnrollmentWorkloadGrant, enrollmentCurrentRevision(t, f, rootID), "replaced")
	administration := *replaced.Request.Administration
	administration.Grants = map[string]map[string]domainGrant{"root": {"read": {Fields: []string{"id"}}}}
	replaced.Request.Administration = &administration
	if _, err := f.server.DomainEnroll(contextBackground(), replaced); err == nil {
		t.Fatal("an administrator acted on grants it does not hold")
	}
}

// An administrator without the store write has nothing of it to hand to a workload.
func TestAdministratorWithoutTheStoreWriteCannotDelegateIt(t *testing.T) {
	f := administrationFixtureOver(t, newWorkloadFixture(t))
	input := administrationInput(f, "admin_wl_proof")
	first := f.enroll(t, input)
	enrollmentAssertAppliedPair(t, f.received(t, first), first, "applied")
	rootID := first.Lease.Binding.RootID
	control := wlAdministrationControl(f, input, EnrollmentWorkloadGrant, enrollmentCurrentRevision(t, f, rootID), "no-store")
	if _, err := f.server.DomainEnroll(contextBackground(), control); err == nil {
		t.Fatal("an administrator delegated a store write it does not hold")
	}
}
