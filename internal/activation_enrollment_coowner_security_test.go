// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCoownerIndependentGrantsNeverUnionPartialDecisions(t *testing.T) {
	profile := EnrollmentProfileRef{"unit-profile", "unit-revision", stagedHash([]byte("unit-profile"))}
	base := domainGrant{Fields: []string{"a", "reference"}}
	owner := domainGrant{Fields: []string{"b", "reference"}, CreateKinds: []string{"role"}, Reference: true, TargetGrantRevision: "unit-g1"}
	c := domainCoownerContribution{"installed", "unit-g1", "unit-command", stagedHash(nil), profile, map[string]domainGrant{"write": owner}}
	acl := domainACL{ContractRevision: domainCoownerACLRevision, Principals: map[string]map[string]domainGrant{"unit-human": {"write": base}}, Coowners: map[string]domainCoownerContribution{"unit-human": c}}
	forest := coownerDecisionForest(t, acl)
	actor := DomainVerified{Kind: "human", PrincipalID: "unit-human", GrantRevision: "unit-g1", ExpiresAt: domainNow() + 30, Scope: aclScope(forest.owned)}
	for _, id := range []string{"unit-copy", "unit-reference"} {
		coownerAssertCompleteDecisions(t, forest, forest.records[id], actor)
	}
}

func coownerDecisionForest(t *testing.T, acl domainACL) *aclForest {
	t.Helper()
	f := newACLForest(t, aclReferences, aclOwned("unit-account", "unit-root"))
	root := domainACL{ContractRevision: domainCoownerACLRevision, Principals: map[string]map[string]domainGrant{}, CreateACLs: map[string]domainACL{"associate": acl}}
	rootValue, err := enrollmentACLValue(root)
	if err != nil {
		t.Fatal(err)
	}
	copyValue, err := enrollmentACLValue(acl)
	if err != nil {
		t.Fatal(err)
	}
	f.records["unit-root"].Metadata[aclKey] = rootValue
	f.records["unit-copy"] = DomainRecord{ID: "unit-copy", Kind: aclKinds["associate"], Metadata: map[string]interface{}{aclKey: copyValue}}
	f.records["unit-reference"] = DomainRecord{ID: "unit-reference", Kind: aclKinds["associate"], Metadata: map[string]interface{}{aclKey: domainACLReferenceValue("unit-root", "associate")}}
	return f
}

func coownerAssertCompleteDecisions(t *testing.T, f *aclForest, record DomainRecord, actor DomainVerified) {
	t.Helper()
	cases := []struct {
		access DomainAccess
		want   string
	}{
		{DomainAccess{Operation: "write"}, "current native action/fields denied"},
		{DomainAccess{Operation: "unknown", Fields: []string{"a"}}, "current native action/fields denied"},
		{DomainAccess{Operation: "write", Fields: []string{"a", "b"}}, "current native field denied: b"},
		{DomainAccess{Operation: "write", Fields: []string{"a"}, Create: true, Kind: "role"}, "current native create denied"},
		{DomainAccess{Operation: "write", Fields: []string{"a", "reference"}, Reference: true}, "current native reference denied"},
		{DomainAccess{Operation: "write", Fields: []string{"a"}}, "allow"},
		{DomainAccess{Operation: "write", Fields: []string{"b", "reference"}, Reference: true, Create: true, Kind: "role"}, "allow"},
	}
	for _, test := range cases {
		if got := aclDecisionText(f.decide(actor, test.access, record)); got != test.want {
			t.Fatalf("%s complete grant decision %v: %q, want %q", record.ID, test.access, got, test.want)
		}
	}
	actor.GrantRevision = "unit-g2"
	if f.decide(actor, DomainAccess{Operation: "write", Fields: []string{"b"}}, record) == nil {
		t.Fatal("stale contribution authorized")
	}
}

func TestCoownerClosedWireAndNoLegacyFallback(t *testing.T) {
	f, root := newCoownerFixture(t)
	i := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-wire", "unit-target", "", "unit-g1")
	raw, _ := CanonicalDomainJSON(i)
	var base map[string]interface{}
	_ = json.Unmarshal(raw, &base)
	for _, damage := range []string{"extra", "receipt-input", "missing-change", "legacy-operation", "unknown-revision", "founder", "same-generation"} {
		t.Run(damage, func(t *testing.T) { coownerRejectWire(t, base, damage) })
	}
}

func coownerRejectWire(t *testing.T, base map[string]interface{}, damage string) {
	t.Helper()
	raw, _ := CanonicalDomainJSON(base)
	var value map[string]interface{}
	_ = json.Unmarshal(raw, &value)
	r := value["request"].(map[string]interface{})
	c := r["coownerChange"].(map[string]interface{})
	switch damage {
	case "extra":
		value["arbitraryGrant"] = true
	case "receipt-input":
		value["mode"] = "receipt"
	case "missing-change":
		delete(r, "coownerChange")
	case "legacy-operation":
		value["contractRevision"], r["contractRevision"] = EnrollmentProofRevision, EnrollmentRevision
		delete(value, "mode")
		delete(r, "coownerChange")
	case "unknown-revision":
		value["contractRevision"] = "manifest-native-enrollment/0.5"
	case "founder":
		r["targetPrincipalId"] = aclFixtureOwner
	case "same-generation":
		c["ownerGrantRevision"] = c["expectedTargetGrantRevision"]
	}
	raw, _ = CanonicalDomainJSON(value)
	if _, err := DecodeEnrollmentInput(raw, 100000); err == nil {
		t.Fatal("invalid co-owner wire accepted", damage)
	}
}

func TestCoownerCurrentAuthorityAndNativeHostMismatchDenied(t *testing.T) {
	for _, damage := range []string{"issuer", "owner", "expired", "purpose", "target", "workload-kind", "native-host", "personal", "unaccepted", "revoked-owner", "pending-target", "precommit-changed"} {
		t.Run(damage, func(t *testing.T) { coownerRejectAuthority(t, damage) })
	}
}

func coownerRejectAuthority(t *testing.T, damage string) {
	t.Helper()
	f, root := newCoownerFixture(t)
	f.corrupt = damage
	i := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-security-"+damage, "unit-target", "", "unit-g1")
	if _, err := f.server.DomainEnroll(context.Background(), i); err == nil {
		t.Fatal("invalid current authority accepted")
	}
}

func TestCoownerConcurrentNativeCASAllowsOnlyOneEffect(t *testing.T) {
	f, root := newCoownerFixture(t)
	f.coowner.concurrent = true // Other callbacks may legitimately overlap unrelated lock holders.
	first := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-cas-one", "unit-target-one", "", "unit-g1-one")
	second := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-cas-two", "unit-target-two", "", "unit-g1-two")
	results := make(chan error, 2)
	for _, input := range []EnrollmentInput{first, second} {
		go func(input EnrollmentInput) {
			_, err := f.server.DomainEnroll(context.Background(), input)
			results <- err
		}(input)
	}
	left, right := <-results, <-results
	if (left == nil) == (right == nil) || len(coownerFixtureACL(t, f, root).Coowners) != 1 || f.server.sourceFence().unknown {
		t.Fatal("native CAS did not produce exactly one settled effect", left, right)
	}
}

func TestCoownerCrossAccountAndSecondLeaseCannotReuseTicket(t *testing.T) {
	f, root := newCoownerFixture(t)
	i, begin := coownerFixtureGrant(t, f, root)
	if _, err := f.server.DomainEnroll(context.Background(), i); err == nil {
		t.Fatal("consumed admission ticket replayed")
	}
	check := f.coowner.checks[1]
	copy := *check.LeaseBinding
	copy.LeaseID = "unit-other-lease"
	check.LeaseBinding = &copy
	if f.coownerTransition(check) {
		t.Fatal("same ticket rebound to second lease")
	}
	actor := EnrollmentVerified{PrincipalID: "unit-added-owner", Kind: "human", GrantRevision: "unit-owner-generation-1", OwnerAuthorized: true, Request: EnrollmentRequest{Operation: EnrollmentReadGrant}}
	other := aclFixtureProvision(t, f, "unit-other-scope")
	if authorizeCoownerControl(actor, coownerFixtureACL(t, f, other), aclFixtureOwner) == nil {
		t.Fatal("co-owner inherited another account")
	}
	if begin.Lease.Binding.RootID != root {
		t.Fatal("owner mutation replaced root")
	}
}

func TestCoownerExceptionAndIndependentPrincipalSurviveRemove(t *testing.T) {
	f, root := newCoownerFixture(t)
	profile := f.config.ProvisioningProfile
	r := coownerFixtureInput(t, f, root, EnrollmentCoownerGrant, "unit-exception", "unit-target", "", "unit-g1").Request
	acl := enrollmentACL(profile, aclFixtureOwner, "role")
	acl.Principals = map[string]map[string]domainGrant{aclFixtureOwner: {"read": {Fields: []string{"id"}}}, "unit-target": {"independent": {Fields: []string{"label"}}}, "unit-unrelated": {"read": {Fields: []string{"label"}}}}
	before := coownerHash(acl.Principals)
	if err := changeCoownerContribution(&acl, r, "role", profile); err != nil {
		t.Fatal(err)
	}
	if !domainEqual(acl.Coowners["unit-target"].Grants["read"].Fields, []string{"id"}) || len(acl.Coowners["unit-target"].Grants) != 1 {
		t.Fatal("exception broadened to full owner profile")
	}
	r.Operation, r.CoownerChange.ExpectedCoownerGrantRevision, r.CoownerChange.OwnerGrantRevision = EnrollmentCoownerRevoke, coownerString("unit-g1"), nil
	if err := changeCoownerContribution(&acl, r, "role", profile); err != nil {
		t.Fatal(err)
	}
	if before != coownerHash(acl.Principals) || len(acl.Coowners) != 0 {
		t.Fatal("independent authority erased/restored")
	}
}

func TestCoownerACLVersionAndBoundRevisionFailClosed(t *testing.T) {
	f, root := newCoownerFixture(t)
	coownerFixtureGrant(t, f, root)
	acl := coownerFixtureACL(t, f, root)
	acl.ContractRevision = domainACLRevision
	if validateCoownerACL(acl) == nil {
		t.Fatal("co-owner layer accepted by old ACL version")
	}
	acl.ContractRevision = domainCoownerACLRevision
	c := acl.Coowners["unit-added-owner"]
	g := c.Grants["read"]
	g.TargetGrantRevision = ""
	c.Grants["read"] = g
	acl.Coowners["unit-added-owner"] = c
	if validateCoownerACL(acl) == nil {
		t.Fatal("unbound founder-like contribution accepted")
	}
}
