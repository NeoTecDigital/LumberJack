// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"testing"
)

func TestAdministrationClosedWireAndLegacySeparation(t *testing.T) {
	for _, damage := range []string{"missing", "null", "extra", "null-name", "false-reference", "extra-grant", "null-kind", "legacy", "input-legacy"} {
		t.Run(damage, func(t *testing.T) {
			f := &enrollmentFixture{config: enrollmentFixtureConfig(t)}
			input := administrationInput(f, "admin_shape_proof")
			raw, _ := CanonicalDomainJSON(input)
			var value map[string]interface{}
			_ = DecodeDomainJSON(raw, &value)
			administrationDamageWire(value, damage)
			raw, _ = CanonicalDomainJSON(value)
			if _, err := DecodeEnrollmentInput(raw, f.config.MaxRequestBytes); err == nil {
				t.Fatal("non-exact administrator wire accepted")
			}
		})
	}
}

func administrationDamageWire(value map[string]interface{}, damage string) {
	request := value["request"].(map[string]interface{})
	admin := request["administration"].(map[string]interface{})
	grant := admin["grants"].(map[string]interface{})["root"].(map[string]interface{})["read"].(map[string]interface{})
	switch damage {
	case "missing":
		delete(request, "administration")
	case "null":
		request["administration"] = nil
	case "extra":
		admin["ownerEmail"] = "not-authority"
	case "null-name":
		admin["name"] = nil
	case "false-reference":
		grant["reference"] = false
	case "extra-grant":
		grant["targetGrantRevision"] = ""
	case "null-kind":
		admin["grants"].(map[string]interface{})["root"] = nil
	case "legacy":
		request["contractRevision"] = EnrollmentRevision
	case "input-legacy":
		value["contractRevision"] = EnrollmentProofRevision
	}
}

func TestAdministrationGrantsBoundedByProtectedProfile(t *testing.T) {
	for _, damage := range []string{"kind", "operation", "wildcard", "field", "duplicate", "create", "reference", "owner", "name", "uuid", "digest", "acl-operation"} {
		t.Run(damage, func(t *testing.T) {
			f := newAdministrationFixture(t)
			input := administrationInput(f, "admin_bound_proof")
			administrationDamageRequest(&input.Request, damage)
			if _, err := f.server.DomainEnroll(context.Background(), input); err == nil {
				t.Fatal("administrator exceeded protected explicit authorization")
			}
		})
	}
}

func administrationDamageRequest(request *EnrollmentRequest, damage string) {
	a := request.Administration
	switch damage {
	case "kind":
		a.Grants["new-kind"] = a.Grants["role"]
	case "operation":
		a.Grants["root"]["new.operation"] = domainGrant{Fields: []string{"id"}}
	case "wildcard":
		a.Grants["root"]["read"] = domainGrant{Fields: []string{"*"}}
	case "field":
		a.Grants["root"]["read"] = domainGrant{Fields: []string{"acl"}}
	case "duplicate":
		a.Grants["root"]["read"] = domainGrant{Fields: []string{"id", "id"}}
	case "create":
		a.Grants["root"]["role.define"] = domainGrant{Fields: []string{"revision"}, CreateKinds: []string{"associate"}}
	case "reference":
		a.Grants["root"]["role.define"] = domainGrant{Fields: []string{"revision"}, Reference: true}
	case "owner":
		a.OwnerPrincipalID = ""
	case "name":
		a.Name = "invalid\nname"
	case "uuid":
		a.AuthorizationID = "not-an-authorization-uuid"
	case "digest":
		a.AuthorizationDigest = "not-an-authorization-digest"
	case "acl-operation":
		request.Operation = EnrollmentReadGrant
	}
}

func TestAdministrationReplayAndRestartBindImmutableAuthorization(t *testing.T) {
	f := newAdministrationFixture(t)
	input := administrationInput(f, "admin_original_proof")
	first := f.enroll(t, input)
	entry := f.server.domain.entries[first.Lease.LeaseID]
	scope := f.server.stagedScopes[entry.owned.Binding.ScopeID]
	receipt, err := f.server.enrollmentHistoryLocked(scope, entry.receiptKey)
	record, recordErr := decodeEnrollmentRecord(receipt.EnrollmentRecord, f.config.MaxRequestBytes)
	if err != nil || recordErr != nil || record.ContractRevision != EnrollmentAdminRecordRevision || !domainEqual(record.Request.Administration, input.Request.Administration) || record.PrincipalID != first.Lease.PrincipalID {
		t.Fatal("actual paired administrator provenance lost", err, recordErr)
	}
	restarted := stagedTestServer(t, f.server.config.Process.DatabasePath)
	if err = restarted.loadFromFile(f.server.statePath()); err != nil {
		t.Fatal(err)
	}
	policy, _ := NewDomainOwnerPolicy(f.config.ACLMetadataKey)
	if err = restarted.ConfigureDomain(f.config, map[string]DomainProduct{"manifest": domainTestProduct{}}, policy); err != nil {
		t.Fatal(err)
	}
	f.server, f.session = restarted, "fresh_real_admin_session"
	input.Proof, input.RequestID = "admin_reopen_proof", "admin_reopen_request"
	replay := f.enroll(t, input)
	if replay.Lease.Binding != first.Lease.Binding || replay.Lease.SessionID == first.Lease.SessionID {
		t.Fatal("reopen changed owner root or reused historical session")
	}
	enrollmentAssertAppliedPair(t, f.received(t, replay), replay, "replayed")
	input.Proof, input.RequestID = "admin_changed_authorization", "admin_changed_request"
	input.Request.Administration.AuthorizationDigest = stagedHash([]byte("changed approval"))
	if _, err = f.server.DomainEnroll(context.Background(), input); err == nil {
		t.Fatal("changed immutable administrator authorization replayed")
	}
}

func TestAdministrationCurrentGrantAndAuthorizationRevocationDenyReplay(t *testing.T) {
	for _, damage := range []string{"authorization", "root", "template", "owner"} {
		t.Run(damage, func(t *testing.T) { administrationRevocation(t, damage) })
	}
}

func administrationRevocation(t *testing.T, damage string) {
	t.Helper()
	f := newAdministrationFixture(t)
	input := administrationInput(f, "admin_before_revoke")
	begin := f.enroll(t, input)
	root, _ := f.server.forest.GetNode(begin.Lease.Binding.RootID)
	policy := &domainOwnerPolicy{key: f.config.ACLMetadataKey}
	acl, _ := policy.acl(DomainRecord{ID: root.ID, Metadata: root.Metadata})
	switch damage {
	case "authorization":
		f.corrupt = "revoked"
	case "root":
		delete(acl.Principals[begin.Lease.PrincipalID], "read")
	case "template":
		delete(acl.CreateACLs["role"].Principals[begin.Lease.PrincipalID], "read")
	case "owner":
		delete(acl.Principals[input.Request.Administration.OwnerPrincipalID], EnrollmentProvision)
	}
	root.Metadata[f.config.ACLMetadataKey], _ = enrollmentACLValue(acl)
	input.Proof, input.RequestID = "admin_after_revoke", "admin_current_request"
	if _, err := f.server.DomainEnroll(context.Background(), input); err == nil {
		t.Fatal("revoked administrator authority replayed")
	}
}

func TestAdministrationHandoffRechecksActualActorAndAuthorization(t *testing.T) {
	for _, damage := range []string{"revoked", "owner", "actor", "expired"} {
		t.Run(damage, func(t *testing.T) {
			f := newAdministrationFixture(t)
			begin := f.enroll(t, administrationInput(f, "admin_before_handoff"))
			f.received(t, begin)
			f.corrupt = damage
			control := DomainControl{Action: "handoff", Epoch: begin.Lease.Epoch, LeaseID: begin.Lease.LeaseID, HostID: f.config.HostID, ChannelToken: f.config.ControlToken, Proof: "admin_current_handoff"}
			if _, err := f.server.DomainControl(context.Background(), control); err == nil {
				t.Fatal("fresh administrator handoff recheck bypassed")
			}
		})
	}
}
