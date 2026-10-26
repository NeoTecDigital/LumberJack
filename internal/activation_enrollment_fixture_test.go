// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
)

type enrollmentFixture struct {
	server         *Server
	config         DomainConfig
	mu             sync.Mutex
	seen           map[string]bool
	session        string
	claim          string
	targetRevision string
	targetState    string
	corrupt        string
}

func newEnrollmentFixture(t *testing.T) *enrollmentFixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	f := &enrollmentFixture{server: stagedTestServer(t, directory), seen: map[string]bool{}, session: "unit-current-session", claim: "unit-owner-claim-1", targetRevision: "unit-accepted-actor-permission-1", targetState: "active"}
	if err := f.server.configureStagedScope(stagedTestBinding(), stagedTestBounds()); err != nil {
		t.Fatal(err)
	}
	f.config = enrollmentFixtureConfig(t)
	callback := httptest.NewServer(http.HandlerFunc(f.callback))
	t.Cleanup(callback.Close)
	f.config.Trust.VerifierEndpoint = callback.URL + "/unit-enrollment-verify"
	policy, err := NewDomainOwnerPolicy(f.config.ACLMetadataKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.server.ConfigureDomain(f.config, map[string]DomainProduct{"manifest": domainTestProduct{}}, policy); err != nil {
		t.Fatal(err)
	}
	return f
}

func enrollmentFixtureConfig(t *testing.T) DomainConfig {
	t.Helper()
	config := domainTestConfig()
	config.Scopes = nil
	config.MaxRequestBytes, config.MaxResponseBytes = 100000, 100000
	config.Trust.MaxBodyBytes, config.Trust.MaxResponseBytes = 100000, 100000
	config.RoleCatalog = []byte(`{"catalogId":"unit-default","catalogVersion":"1","roles":[]}`)
	profile := DomainProvisioningProfile{ContractRevision: EnrollmentProfileRevision, AccountRootKind: "formalentity", ProfileRef: EnrollmentProfileRef{ProfileID: "unit-profile", ProfileRevision: "unit-revision-2"}, Bounds: stagedTestBounds(), OwnerGrants: map[string]map[string]domainGrant{}}
	profile.Layout = enrollmentFixtureLayout(config.RoleCatalog)
	enrollmentFixtureGrants(&profile)
	digest, err := DomainProvisioningProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	profile.ProfileRef.ProfileDigest = digest
	config.ProvisioningProfile = &profile
	return config
}

func enrollmentFixtureLayout(catalog []byte) DomainLayout {
	layout := DomainLayout{ContractRevision: "manifest-associates/0.2", Kinds: map[string]string{}, Fields: map[string]string{}, Routes: map[string]DomainRoute{}, Profiles: map[string]map[string][]string{}}
	layout.CatalogRef, _ = CanonicalDomainJSON(map[string]string{"catalogId": "unit-default", "catalogVersion": "1", "catalogDigest": stagedHash(catalog)})
	for _, kind := range enrollmentKinds {
		layout.Kinds[kind] = "unit-native-" + kind
	}
	for _, field := range []string{"accountId", "kind", "label", "roleIds", "requirementIds", "functionIds", "contextLinks", "defaultKey", "roleOrder", "roleCatalogRef"} {
		layout.Fields[field] = field
	}
	for _, operation := range enrollmentActions {
		layout.Routes[operation] = DomainRoute{Method: "POST", Target: "/unit/manifest/" + operation}
		layout.Profiles[operation] = enrollmentFixtureFields(operation)
	}
	return layout
}

func enrollmentFixtureFields(operation string) map[string][]string {
	profiles := map[string][]string{}
	for _, kind := range enrollmentKinds {
		profiles[kind] = []string{"id", "label", "reference"}
	}
	if operation != "read" {
		profiles["root"] = []string{"revision"}
	}
	return profiles
}

func enrollmentFixtureGrants(profile *DomainProvisioningProfile) {
	for _, kind := range enrollmentKinds {
		profile.OwnerGrants[kind] = map[string]domainGrant{}
	}
	for operation, fields := range profile.Layout.Profiles {
		enrollmentFixtureOperationGrants(profile, operation, fields)
	}
	for _, operation := range []string{EnrollmentProvision, EnrollmentReadGrant, EnrollmentReadRevoke} {
		profile.OwnerGrants["root"][operation] = domainGrant{Fields: []string{"acl"}}
	}
	profile.OwnerGrants["root"]["role.define"] = domainGrant{Fields: []string{"revision"}, CreateKinds: []string{"role"}}
}

func enrollmentFixtureOperationGrants(profile *DomainProvisioningProfile, operation string, profiles map[string][]string) {
	for kind, fields := range profiles {
		profile.OwnerGrants[kind][operation] = domainGrant{Fields: append([]string(nil), fields...), Reference: domainContains(fields, "reference")}
	}
}

func (f *enrollmentFixture) callback(w http.ResponseWriter, r *http.Request) {
	var check EnrollmentCheck
	if json.NewDecoder(r.Body).Decode(&check) != nil || r.Header.Get("Authorization") != "Bearer "+f.config.Trust.ChannelToken {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen[check.Proof] {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	f.seen[check.Proof] = true
	actor := f.actor(check)
	raw, _ := CanonicalDomainJSON(actor)
	var value map[string]interface{}
	_ = DecodeDomainJSON(raw, &value)
	f.corruptActor(value)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (f *enrollmentFixture) actor(check EnrollmentCheck) EnrollmentVerified {
	actor := EnrollmentVerified{ContractRevision: EnrollmentProofRevision, PrincipalID: "unit-verified-momentum-human", Kind: "human", SessionID: f.session, Scope: check.Request.Scope, RequestID: check.RequestID, Request: check.Request, RequestFingerprint: check.RequestFingerprint, GrantRevision: f.claim, AuthorityPolicyRevision: "unit-explicit-mapped-policy", AuthorityResourceRevision: "unit-pending-account-resource", ExpiresAt: domainNow() + 30, Issuer: f.config.Trust.Issuer, Audience: check.Audience, Phase: check.Phase, LeaseBinding: check.LeaseBinding, ProofBinding: stagedHash([]byte(check.Proof)), OwnerAuthorized: true, Purpose: check.Request.Operation}
	if check.Request.TargetPrincipalID != nil {
		actor.PrincipalReference = f.target(actor)
	}
	return actor
}

func (f *enrollmentFixture) target(actor EnrollmentVerified) *DomainPrincipalReference {
	revision := f.targetRevision
	ref := &DomainPrincipalReference{ActorPrincipalID: actor.PrincipalID, ActorSessionID: actor.SessionID, AccountID: actor.Scope.AccountID, PrincipalID: *actor.Request.TargetPrincipalID, Purpose: actor.Purpose, RequestID: actor.RequestID, ActorGrantRevision: actor.GrantRevision, TargetGrantRevision: &revision, EvidenceRevision: "unit-registered-actor-evidence", AuthorityPolicyRevision: actor.AuthorityPolicyRevision, CheckedAt: domainNow() - 1, ValidUntil: domainNow() + 40, TargetEligibility: f.targetState}
	if f.targetState == "revoked" {
		ref.TargetGrantRevision = nil
	}
	return ref
}

func (f *enrollmentFixture) corruptActor(value map[string]interface{}) {
	switch f.corrupt {
	case "issuer":
		value["issuer"] = "untrusted-issuer"
	case "kind":
		value["kind"] = "integration_actor"
	case "owner":
		value["ownerAuthorized"] = false
	case "expired":
		value["expiresAt"] = domainNow() - 1
	case "proof":
		value["proofBinding"] = stagedHash([]byte("another-proof"))
	case "extra":
		value["roleLabel"] = "Owner"
	case "missing":
		delete(value, "principalReference")
	case "purpose":
		value["purpose"] = "identity.read"
	case "target":
		value["principalReference"].(map[string]interface{})["accountId"] = "another-account"
	}
}

func (f *enrollmentFixture) input(operation, account, command, proof, revision string, target *string) EnrollmentInput {
	return EnrollmentInput{ContractRevision: EnrollmentProofRevision, RequestID: "unit-request-" + proof, Proof: proof, Request: EnrollmentRequest{ContractRevision: EnrollmentRevision, Scope: DomainScope{AccountID: account, Product: "manifest"}, CommandID: command, ExpectedRevision: revision, Operation: operation, TargetPrincipalID: target, ProfileRef: f.config.ProvisioningProfile.ProfileRef}}
}

func (f *enrollmentFixture) enroll(t *testing.T, input EnrollmentInput) DomainBegin {
	t.Helper()
	raw, err := CanonicalDomainJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := f.server.DomainEnrollJSON(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return begin
}

func (f *enrollmentFixture) control(t *testing.T, begin DomainBegin, action string) DomainControlResult {
	t.Helper()
	input := DomainControl{Action: action, Epoch: begin.Lease.Epoch, LeaseID: begin.Lease.LeaseID, HostID: f.config.HostID, ChannelToken: f.config.ControlToken}
	result, err := f.server.DomainControl(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (f *enrollmentFixture) received(t *testing.T, begin DomainBegin) DomainReceived {
	t.Helper()
	f.control(t, begin, "adopt")
	return f.control(t, begin, "receive").Value.(DomainReceived)
}
