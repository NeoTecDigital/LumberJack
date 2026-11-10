// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

type coownerFixtureAuthority struct {
	principal         string
	grant             string
	phases            map[string]string
	deadlines         map[string]float64
	leases            map[string]DomainLease
	checks            []EnrollmentCheck
	denyPrecommit     bool
	concurrent        bool
	precommitDeadline float64
}

func newCoownerFixture(t *testing.T) (*enrollmentFixture, string) {
	t.Helper()
	f := newEnrollmentFixture(t)
	f.coowner = &coownerFixtureAuthority{principal: aclFixtureOwner, grant: f.claim, phases: map[string]string{}, deadlines: map[string]float64{}, leases: map[string]DomainLease{}}
	root := aclFixtureProvision(t, f, "unit-coowner-account")
	return f, root
}

func (f *enrollmentFixture) coownerCallback(w http.ResponseWriter, check EnrollmentCheck) {
	if !f.coowner.concurrent && !f.coownerCallbackLocksFree() {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.coowner == nil || !f.coownerTransition(check) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	actor := f.coownerActor(check)
	raw, _ := CanonicalDomainJSON(actor)
	var value map[string]interface{}
	_ = DecodeDomainJSON(raw, &value)
	f.corruptActor(value)
	coownerCorruptAuthority(value, check, f.corrupt)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (f *enrollmentFixture) coownerCallbackLocksFree() bool {
	if !f.server.forestMutex.TryLock() {
		return false
	}
	f.server.forestMutex.Unlock()
	if !f.server.domain.mu.TryLock() {
		return false
	}
	f.server.domain.mu.Unlock()
	return true
}

func coownerCorruptAuthority(value map[string]interface{}, check EnrollmentCheck, corruption string) {
	authority := value["coownerAuthority"].(map[string]interface{})
	switch corruption {
	case "personal":
		authority["accountKind"] = "personal"
	case "unaccepted":
		authority["targetAccepted"] = false
	case "revoked-owner":
		authority["actorGrantState"] = "revoked"
	case "pending-target":
		authority["targetNativeState"] = "revoking"
	case "precommit-changed":
		if check.Phase == "precommit" {
			value["authorityResourceRevision"] = "unit-replaced-resource"
		}
	}
}

func (f *enrollmentFixture) coownerTransition(check EnrollmentCheck) bool {
	c := f.coowner
	if check.EnrollmentCoownerWire == nil || check.NativeHostID != f.config.HostID {
		return false
	}
	prior := c.phases[check.Proof]
	if check.Phase == "precommit" {
		if c.denyPrecommit || prior != "admission" || check.LeaseBinding == nil {
			return false
		}
		c.leases[check.Proof] = *check.LeaseBinding
	} else if prior != "" {
		return false
	}
	if prior == "" {
		c.deadlines[check.Proof] = domainNow() + 30
	}
	c.phases[check.Proof] = check.Phase
	c.checks = append(c.checks, check)
	return true
}

func (f *enrollmentFixture) coownerActor(check EnrollmentCheck) EnrollmentVerified {
	actor := f.actor(check)
	actor.ContractRevision, actor.PrincipalID, actor.GrantRevision = EnrollmentCoownerProofRevision, f.coowner.principal, f.coowner.grant
	actor.EnrollmentCoownerWire = check.EnrollmentCoownerWire
	actor.ExpiresAt = f.coowner.deadlines[check.Proof]
	if check.Phase == "precommit" && f.coowner.precommitDeadline != 0 {
		actor.ExpiresAt = f.coowner.precommitDeadline
	}
	actor.CoownerAuthority = &EnrollmentCoownerAuthority{AccountKind: "organization", CommandRevision: "unit-reserved-command-revision", TargetKind: "human", TargetAccepted: true, TargetNativeState: "confirmed", ActorGrantState: "active"}
	actor.PrincipalReference = f.target(actor)
	if check.Mode != "apply" {
		actor.PrincipalReference = nil
		actor.CoownerAuthority.ReceiptAuthorized = true
		actor.OwnerAuthorized = actor.PrincipalID != *check.ReceiptActorPrincipalID
	}
	return actor
}

func coownerString(value string) *string { return &value }

func coownerFixtureInput(t *testing.T, f *enrollmentFixture, root, operation, command, target, old, next string) EnrollmentInput {
	t.Helper()
	i := f.input(operation, "unit-coowner-account", command, "unit-proof-"+command, enrollmentCurrentRevision(t, f, root), &target)
	i.ContractRevision, i.Request.ContractRevision, i.Mode = EnrollmentCoownerProofRevision, EnrollmentCoownerRevision, "apply"
	c := &EnrollmentCoownerChange{FounderPrincipalID: aclFixtureOwner, OwnershipRevision: "unit-structure-reservation", ExpectedTargetGrantRevision: coownerString(f.targetRevision)}
	if old != "" {
		c.ExpectedCoownerGrantRevision = coownerString(old)
	}
	if next != "" {
		c.OwnerGrantRevision = coownerString(next)
	}
	i.Request.CoownerChange = c
	return i
}

func coownerFixtureACL(t *testing.T, f *enrollmentFixture, id string) domainACL {
	t.Helper()
	node, err := f.server.forest.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	policy := &domainOwnerPolicy{key: f.config.ACLMetadataKey}
	acl, err := policy.acl(DomainRecord{ID: id, Kind: node.Kind, Metadata: node.Metadata})
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

func coownerFixtureGrant(t *testing.T, f *enrollmentFixture, root string) (EnrollmentInput, DomainBegin) {
	t.Helper()
	i := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-add-coowner", "unit-added-owner", "", "unit-owner-generation-1")
	begin := f.enroll(t, i)
	enrollmentAssertAppliedPair(t, f.received(t, begin), begin, "applied")
	return i, begin
}

func TestCoownerActualPairCurrentRightsAndFounderProvenance(t *testing.T) {
	f, root := newCoownerFixture(t)
	profile := f.config.ProvisioningProfile.ProfileRef
	member := "unit-added-owner"
	f.enroll(t, f.input(EnrollmentReadGrant, "unit-coowner-account", "unit-member-first", "unit-member-proof", enrollmentCurrentRevision(t, f, root), &member))
	before := coownerFixtureACL(t, f, root)
	_, begin := coownerFixtureGrant(t, f, root)
	after := coownerFixtureACL(t, f, root)
	if !domainEqual(before.Principals, after.Principals) || after.ContractRevision != domainCoownerACLRevision {
		t.Fatal("co-owner replaced independent principal grants")
	}
	actor := DomainVerified{Kind: "human", PrincipalID: member, GrantRevision: "unit-owner-generation-1", ExpiresAt: domainNow() + 30}
	access := DomainAccess{Operation: "role.define", Fields: []string{"revision"}, Create: true, Kind: "role"}
	if !coownerGrantAllows(actor, after.Coowners[member], access) {
		t.Fatal("own revision did not grant real write/create authority")
	}
	actor.GrantRevision = f.targetRevision
	if coownerGrantAllows(actor, after.Coowners[member], access) {
		t.Fatal("member g0 gained owner g1 authority")
	}
	node, _ := f.server.forest.GetNode(root)
	if node.CreatedBy != aclFixtureOwner || profile != f.config.ProvisioningProfile.ProfileRef || begin.Lease.Binding.RootID != root {
		t.Fatal("founder/profile/native root identity changed")
	}
	if len(f.coowner.checks) != 2 || f.coowner.checks[0].Phase != "admission" || f.coowner.checks[1].Phase != "precommit" || f.coowner.checks[0].Proof != f.coowner.checks[1].Proof {
		t.Fatal("synchronous same-ticket transition missing")
	}
}

func TestCoownerCanExerciseExistingMemberControlWithOwnGrant(t *testing.T) {
	f, root := newCoownerFixture(t)
	coownerFixtureGrant(t, f, root)
	acl := coownerFixtureACL(t, f, root)
	actor := EnrollmentVerified{PrincipalID: "unit-added-owner", Kind: "human", GrantRevision: "unit-owner-generation-1", OwnerAuthorized: true, Request: EnrollmentRequest{Operation: EnrollmentReadGrant}}
	if err := authorizeCoownerControl(actor, acl, aclFixtureOwner); err != nil {
		t.Fatal(err)
	}
	actor.GrantRevision = "unit-stale-owner"
	if authorizeCoownerControl(actor, acl, aclFixtureOwner) == nil {
		t.Fatal("stale owner control permitted")
	}
	f.coowner.principal, f.coowner.grant = "unit-added-owner", "unit-owner-generation-1"
	target := "unit-next-member"
	begin := f.enroll(t, f.input(EnrollmentReadGrant, "unit-coowner-account", "unit-coowner-member-grant", "unit-coowner-member-proof", enrollmentCurrentRevision(t, f, root), &target))
	if begin.Lease.PrincipalID != "unit-added-owner" {
		t.Fatal("member control substituted founder")
	}
	enrollmentAssertAppliedPair(t, f.received(t, begin), begin, "applied")
}

func TestCoownerCanGrantAnotherOwnerWithOwnNativeGeneration(t *testing.T) {
	f, root := newCoownerFixture(t)
	coownerFixtureGrant(t, f, root)
	f.coowner.principal, f.coowner.grant = "unit-added-owner", "unit-owner-generation-1"
	i := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-second-owner", "unit-another-owner", "", "unit-second-owner-g1")
	begin := f.enroll(t, i)
	enrollmentAssertAppliedPair(t, f.received(t, begin), begin, "applied")
	acl := coownerFixtureACL(t, f, root)
	if begin.Lease.PrincipalID != "unit-added-owner" || acl.Coowners["unit-another-owner"].GrantCommandID != i.Request.CommandID || acl.Coowners["unit-added-owner"].GrantRevision != "unit-owner-generation-1" {
		t.Fatal("genuine own-identity co-owner delegation missing")
	}
}

func TestCoownerExistingCopiesFollowersFutureTemplatesAndRevocation(t *testing.T) {
	f, root := newCoownerFixture(t)
	copies := aclSeedRecords(t, f, root, "unit-copy", 1, aclFixtureCopy(t, f, root))
	followers := aclSeedRecords(t, f, root, "unit-follow", 2, aclFixtureFollower(root))
	_, begin := coownerFixtureGrant(t, f, root)
	if aclFixtureReceipt(t, f, begin).Followers["role"] != 2 {
		t.Fatal("follower counts absent")
	}
	if coownerFixtureACL(t, f, copies[0]).Coowners["unit-added-owner"].State != "installed" || !aclFixtureHasReference(t, f, followers[0]) {
		t.Fatal("copies/followers not covered")
	}
	acl := coownerFixtureACL(t, f, root)
	if acl.CreateACLs["role"].Coowners["unit-added-owner"].GrantRevision != "unit-owner-generation-1" {
		t.Fatal("future template missing owner revision")
	}
	f.targetRevision = "unit-owner-generation-1"
	revoke := coownerFixtureInput(t, f, root, EnrollmentCoownerRevoke, "unit-remove-coowner", "unit-added-owner", f.targetRevision, "")
	f.enroll(t, revoke)
	after := coownerFixtureACL(t, f, root)
	if after.Coowners["unit-added-owner"].State != "revoked" || len(after.CreateACLs["role"].Coowners) != 0 || len(coownerFixtureACL(t, f, copies[0]).Coowners) != 0 {
		t.Fatal("revocation left native owner authority")
	}
}

func TestCoownerPrecommitFailureCannotPublishCandidate(t *testing.T) {
	f, root := newCoownerFixture(t)
	f.coowner.denyPrecommit = true
	before := enrollmentCurrentRevision(t, f, root)
	i := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-denied-precommit", "unit-added-owner", "", "unit-owner-generation-1")
	if _, err := f.server.DomainEnroll(context.Background(), i); err == nil {
		t.Fatal("missing precommit accepted")
	}
	if enrollmentCurrentRevision(t, f, root) != before || f.server.stagedScopes[enrollmentScopeID(i.Request.Scope.AccountID)].pending != nil {
		t.Fatal("unwritten candidate leaked")
	}
}

func TestCoownerPrecommitRetainsShorterDeadlineBeforePairedWrite(t *testing.T) {
	f, root := newCoownerFixture(t)
	f.coowner.precommitDeadline = domainNow() + 20
	i := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-shorter-precommit", "unit-added-owner", "", "unit-owner-generation-1")
	actual, observed := f.server.stateWriter.write, false
	f.server.stateWriter.write = func(snapshot stateSnapshot) error {
		f.server.domain.mu.Lock()
		entry := f.server.domain.entries[f.coowner.leases[i.Proof].LeaseID]
		valid := entry != nil && entry.enrollment.actor.Phase == "precommit" && entry.enrollment.actor.ExpiresAt == f.coowner.precommitDeadline
		f.server.domain.mu.Unlock()
		if !valid {
			t.Error("paired write retained stale admission authority/deadline")
		}
		observed = true
		return actual(snapshot)
	}
	begin := f.enroll(t, i)
	if !observed || f.server.domain.entries[begin.Lease.LeaseID].enrollment.actor.ExpiresAt != f.coowner.precommitDeadline {
		t.Fatal("shorter callback expiry was not retained")
	}
	entry := f.server.domain.entries[begin.Lease.LeaseID]
	f.server.domain.mu.Lock()
	entry.enrollment.actor.ExpiresAt = domainNow() - 1
	f.server.domain.mu.Unlock()
	if f.server.domain.enrollmentLive(entry) == nil {
		t.Fatal("prewrite live check ignored expired refreshed authority")
	}
}
