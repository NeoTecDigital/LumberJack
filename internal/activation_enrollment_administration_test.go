// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newAdministrationFixture(t *testing.T) *enrollmentFixture {
	t.Helper()
	return administrationFixtureOver(t, newEnrollmentFixture(t))
}

func administrationFixtureOver(t *testing.T, f *enrollmentFixture) *enrollmentFixture {
	t.Helper()
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var check EnrollmentCheck
		if json.NewDecoder(r.Body).Decode(&check) != nil || check.ContractRevision != EnrollmentAdminProofRevision {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.seen[check.Proof] || f.corrupt == "revoked" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.seen[check.Proof] = true
		actor := f.actor(check)
		actor.ContractRevision, actor.OwnerAuthorized, actor.AdministratorAuthorized = EnrollmentAdminProofRevision, false, true
		raw, _ := CanonicalDomainJSON(actor)
		var value map[string]interface{}
		_ = DecodeDomainJSON(raw, &value)
		administrationCorruptActor(value, f.corrupt)
		_ = json.NewEncoder(w).Encode(value)
	}))
	t.Cleanup(callback.Close)
	f.config.Trust.VerifierEndpoint = callback.URL + "/unit-administration-verify"
	f.server.domain.config.Trust.VerifierEndpoint = callback.URL + "/unit-administration-verify"
	return f
}

func administrationCorruptActor(value map[string]interface{}, damage string) {
	switch damage {
	case "owner":
		value["ownerAuthorized"] = true
	case "missing-admin":
		delete(value, "administratorAuthorized")
	case "false-admin":
		value["administratorAuthorized"] = false
	case "legacy":
		value["contractRevision"] = EnrollmentProofRevision
	case "actor":
		value["principalId"] = "original-jay-owner"
	case "expired":
		value["expiresAt"] = domainNow() - 1
	}
}

func administrationInput(f *enrollmentFixture, proof string) EnrollmentInput {
	input := f.input(EnrollmentProvision, "explicit-administrator-account", "stable-administrator-command", proof, "absent", nil)
	input.ContractRevision, input.Request.ContractRevision = EnrollmentAdminProofRevision, EnrollmentAdminRevision
	input.Request.Administration = &EnrollmentAdministration{
		OwnerPrincipalID: "original-jay-owner", Name: "P&G – native organization",
		AuthorizationID: "66cbb392-26df-45ec-bbfe-5d8592609391", AuthorizationDigest: stagedHash([]byte("approved immutable spec")),
		Grants: map[string]map[string]domainGrant{
			"root": {"read": {Fields: []string{"id"}}, "role.define": {Fields: []string{"revision"}, CreateKinds: []string{"role"}}},
			"role": {"read": {Fields: []string{"id"}, Reference: true}},
		},
	}
	return input
}

func TestAdministrationPreservesOwnerActorNameAndFutureACLs(t *testing.T) {
	f := newAdministrationFixture(t)
	input := administrationInput(f, "admin_initial_proof")
	begin := f.enroll(t, input)
	received := f.received(t, begin)
	entry := f.server.domain.entries[begin.Lease.LeaseID]
	index, _ := stagedForestIndex(stagedTestDisk(t, f.server))
	root, account := index[begin.Lease.Binding.RootID], index[entry.owned.Binding.AccountRootID]
	if root.CreatedBy != input.Request.Administration.OwnerPrincipalID || account.CreatedBy != root.CreatedBy || root.Name != input.Request.Administration.Name || account.Name != root.Name {
		t.Fatal("explicit owner or native display name lost")
	}
	if begin.Lease.PrincipalID != "unit-verified-momentum-human" || received.Pair.PrincipalID != begin.Lease.PrincipalID {
		t.Fatal("administrator was impersonated as owner")
	}
	policy := &domainOwnerPolicy{key: f.config.ACLMetadataKey}
	acl, err := policy.acl(DomainRecord{ID: root.ID, Metadata: root.Metadata})
	if err != nil || !domainEqual(acl.Principals[root.CreatedBy], f.config.ProvisioningProfile.OwnerGrants["root"]) || !domainEqual(acl.Principals[begin.Lease.PrincipalID], input.Request.Administration.Grants["root"]) {
		t.Fatal("administrator copied/replaced owner privileges", err)
	}
	if !domainEqual(acl.CreateACLs["role"].Principals[begin.Lease.PrincipalID], input.Request.Administration.Grants["role"]) || len(acl.CreateACLs["associate"].Principals[begin.Lease.PrincipalID]) != 0 {
		t.Fatal("future ACL delegation broadened/lost")
	}
	administrationAssertResponse(t, received, input)
	administrationAssertHandoff(t, f, begin, "admin_handoff_proof")
}

func administrationAssertResponse(t *testing.T, received DomainReceived, input EnrollmentInput) {
	t.Helper()
	var envelope map[string]interface{}
	_ = DecodeDomainJSON(received.Body, &envelope)
	if envelope["contractRevision"] != EnrollmentAdminRevision || envelope["receipt"].(map[string]interface{})["ownerPrincipalId"] != input.Request.Administration.OwnerPrincipalID {
		t.Fatal("administrator receipt revision/explicit owner mismatch")
	}
}

func administrationAssertHandoff(t *testing.T, f *enrollmentFixture, begin DomainBegin, proof string) {
	t.Helper()
	control := DomainControl{Action: "handoff", Epoch: begin.Lease.Epoch, LeaseID: begin.Lease.LeaseID, HostID: f.config.HostID, ChannelToken: f.config.ControlToken, Proof: proof}
	if _, err := f.server.DomainControl(context.Background(), control); err != nil {
		t.Fatal(err)
	}
}

func TestAdministrationSamePrincipalRetainsOwnerRights(t *testing.T) {
	f := newAdministrationFixture(t)
	input := administrationInput(f, "admin_owner_proof")
	input.Request.Administration.OwnerPrincipalID = "unit-verified-momentum-human"
	begin := f.enroll(t, input)
	root, _ := f.server.forest.GetNode(begin.Lease.Binding.RootID)
	policy := &domainOwnerPolicy{key: f.config.ACLMetadataKey}
	acl, _ := policy.acl(DomainRecord{ID: root.ID, Metadata: root.Metadata})
	if !domainEqual(acl.Principals[begin.Lease.PrincipalID], f.config.ProvisioningProfile.OwnerGrants["root"]) {
		t.Fatal("bounded administrator grants replaced same-principal owner rights")
	}
	f.received(t, begin)
	administrationAssertHandoff(t, f, begin, "admin_owner_handoff")
}

func TestAdministrationCallbackNeverBecomesOwnerOrDefaultAuthority(t *testing.T) {
	for _, damage := range []string{"owner", "missing-admin", "false-admin", "legacy", "expired", "revoked"} {
		t.Run(damage, func(t *testing.T) {
			f := newAdministrationFixture(t)
			f.corrupt = damage
			if _, err := f.server.DomainEnroll(context.Background(), administrationInput(f, "admin_denied_proof")); err == nil {
				t.Fatal("invalid administrator callback accepted")
			}
		})
	}
}
