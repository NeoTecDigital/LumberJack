// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

const aclFixtureOwner = "unit-verified-momentum-human"

func aclSeedRecords(t *testing.T, f *enrollmentFixture, rootID, prefix string, count int, value func() interface{}) []string {
	t.Helper()
	return aclSeedKind(t, f, rootID, "role", prefix, count, value)
}

func aclSeedKind(t *testing.T, f *enrollmentFixture, rootID, kind, prefix string, count int, value func() interface{}) []string {
	t.Helper()
	f.server.forestMutex.Lock()
	defer f.server.forestMutex.Unlock()
	root, err := f.server.forest.GetNode(rootID)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor stagedDescriptor
	if err = decodeStagedInternal(root.CommandReceipts[stagedScopeKey], &descriptor); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, count)
	for index := 0; index < count; index++ {
		id := fmt.Sprintf("%s-%03d", prefix, index)
		metadata := map[string]interface{}{f.config.ACLMetadataKey: value()}
		root.Children[id] = &core.Node{ID: id, Name: id, Kind: f.config.ProvisioningProfile.Layout.Kinds[kind], Parents: map[string]string{root.ID: root.Name}, Children: map[string]*core.Node{}, Metadata: metadata, CommandReceipts: map[string]interface{}{stagedScopeKey: descriptor}}
		ids = append(ids, id)
	}
	return ids
}

func aclFixtureFollower(rootID string) func() interface{} {
	return func() interface{} { return domainACLReferenceValue(rootID, "role") }
}

func aclFixtureCopy(t *testing.T, f *enrollmentFixture, rootID string) func() interface{} {
	t.Helper()
	root, err := f.server.forest.GetNode(rootID)
	if err != nil {
		t.Fatal(err)
	}
	return func() interface{} {
		policy := &domainOwnerPolicy{key: f.config.ACLMetadataKey}
		value, err := legacyCreateACL(policy, DomainVerified{PrincipalID: aclFixtureOwner}, "role.define", "role", DomainRecord{ID: rootID, Metadata: root.Metadata})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
}

func aclFixtureProvision(t *testing.T, f *enrollmentFixture, account string) string {
	t.Helper()
	begin := f.enroll(t, f.input(EnrollmentProvision, account, "unit-create-"+account, "unit-proof-"+account, "absent", nil))
	enrollmentAssertAppliedPair(t, f.received(t, begin), begin, "applied")
	return begin.Lease.Binding.RootID
}

func aclFixtureDecision(t *testing.T, f *enrollmentFixture, account, principal, id string) error {
	t.Helper()
	d := f.server.domain
	scope := DomainScope{AccountID: account, Product: "manifest"}
	owned := d.scopes[scope]
	f.server.forestMutex.RLock()
	defer f.server.forestMutex.RUnlock()
	view, err := f.server.domainScopeViewLocked(owned, false, true)
	if err != nil {
		t.Fatal(err)
	}
	actor := DomainVerified{PrincipalID: principal, Kind: "human", GrantRevision: f.targetRevision, ExpiresAt: domainNow() + 30, Scope: scope}
	return d.authorizeDomainRecord(actor, DomainAccess{Operation: "read", Fields: []string{"id", "label"}}, view, view.Records[id])
}

func aclFixtureGrant(t *testing.T, f *enrollmentFixture, operation, account, rootID, target, tag string) DomainBegin {
	t.Helper()
	begin := f.enroll(t, f.input(operation, account, "unit-"+tag, "unit-proof-"+tag, enrollmentCurrentRevision(t, f, rootID), &target))
	enrollmentAssertAppliedPair(t, f.received(t, begin), begin, "applied")
	return begin
}

func aclFixtureReceipt(t *testing.T, f *enrollmentFixture, begin DomainBegin) stagedReceipt {
	t.Helper()
	entry := f.server.domain.entries[begin.Lease.LeaseID]
	receipt, err := f.server.enrollmentHistoryLocked(f.server.stagedScopes[entry.owned.Binding.ScopeID], entry.receiptKey)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func aclFixtureHasReference(t *testing.T, f *enrollmentFixture, id string) bool {
	t.Helper()
	node, err := stagedTestDisk(t, f.server).GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	_, isReference, err := domainACLReferenceOf(node.Metadata[f.config.ACLMetadataKey])
	if err != nil {
		t.Fatal(err)
	}
	return isReference
}

// Records following the template take the member's grant and revoke with the one write to the
// root, on a real paired command, and stay references on disk.
func TestEnrollmentFollowersChangeWithTheirTemplateAboveTheChangeBound(t *testing.T) {
	f := newEnrollmentFixture(t)
	rootID := aclFixtureProvision(t, f, "unit-followers")
	ids := aclSeedRecords(t, f, rootID, "follower", stagedTestBounds().MaxChanges+10, aclFixtureFollower(rootID))
	target := "unit-followers-member"
	if err := aclFixtureDecision(t, f, "unit-followers", target, ids[0]); err == nil {
		t.Fatal("member read before any grant")
	}
	grant := aclFixtureGrant(t, f, EnrollmentReadGrant, "unit-followers", rootID, target, "grant")
	receipt := aclFixtureReceipt(t, f, grant)
	if len(receipt.Targets) != 1 || receipt.Targets[0].NodeID != rootID {
		t.Fatalf("followers were rewritten: %d targets", len(receipt.Targets))
	}
	if err := aclFixtureDecision(t, f, "unit-followers", target, ids[len(ids)-1]); err != nil {
		t.Fatal("granted member denied through the template", err)
	}
	if !aclFixtureHasReference(t, f, ids[0]) {
		t.Fatal("a grant replaced a reference with a copy")
	}
	aclFixtureGrant(t, f, EnrollmentReadRevoke, "unit-followers", rootID, target, "revoke")
	if err := aclFixtureDecision(t, f, "unit-followers", target, ids[0]); err == nil {
		t.Fatal("revoked member still reads through the template")
	}
}

// The same change on stored copies is one write per record, and the change bound still refuses it.
func TestEnrollmentCopiesAboveTheChangeBoundAreStillRefused(t *testing.T) {
	f := newEnrollmentFixture(t)
	rootID := aclFixtureProvision(t, f, "unit-copies")
	aclSeedRecords(t, f, rootID, "copy", stagedTestBounds().MaxChanges+10, aclFixtureCopy(t, f, rootID))
	target := "unit-copies-member"
	input := f.input(EnrollmentReadGrant, "unit-copies", "unit-grant", "unit-proof-grant", enrollmentCurrentRevision(t, f, rootID), &target)
	raw, err := CanonicalDomainJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.server.DomainEnrollJSON(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "exceeds change bound") {
		t.Fatal("copies must keep their bound", err)
	}
}

func aclFixtureRestart(t *testing.T, f *enrollmentFixture) {
	t.Helper()
	if err := f.server.persistState(f.server.statePath()); err != nil {
		t.Fatal(err)
	}
	restarted := stagedTestServer(t, f.server.config.Process.DatabasePath)
	if err := restarted.loadFromFile(f.server.statePath()); err != nil {
		t.Fatal(err)
	}
	policy, err := NewDomainOwnerPolicy(f.config.ACLMetadataKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.ConfigureDomain(f.config, map[string]DomainProduct{"manifest": domainTestProduct{}}, policy); err != nil {
		t.Fatal(err)
	}
	f.server = restarted
}

func aclFixtureListBytes(t *testing.T, f *enrollmentFixture, id string) string {
	t.Helper()
	node, err := f.server.forest.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalDomainJSON(node.Metadata[f.config.ACLMetadataKey])
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// A forest of stored copies reopens unchanged, takes new records as references, and both answer
// the same way through a grant and a revoke on either side of a restart.
func TestExistingCopiesReopenUnchangedAndMixWithReferences(t *testing.T) {
	f := newEnrollmentFixture(t)
	rootID := aclFixtureProvision(t, f, "unit-mixed")
	copies := aclSeedRecords(t, f, rootID, "copy", 3, aclFixtureCopy(t, f, rootID))
	followers := aclSeedRecords(t, f, rootID, "follower", 3, aclFixtureFollower(rootID))
	aclFixtureRestart(t, f)
	before := enrollmentCurrentRevision(t, f, rootID)
	stored := aclFixtureListBytes(t, f, copies[0])
	aclFixtureRestart(t, f)
	if enrollmentCurrentRevision(t, f, rootID) != before || aclFixtureListBytes(t, f, copies[0]) != stored {
		t.Fatal("reopening rewrote stored state")
	}
	target := "unit-mixed-member"
	assert := func(step string, allowed bool) {
		t.Helper()
		for _, id := range append(append([]string{}, copies...), followers...) {
			if err := aclFixtureDecision(t, f, "unit-mixed", target, id); (err == nil) != allowed {
				t.Fatalf("%s: %s decided %v", step, id, err)
			}
			if err := aclFixtureDecision(t, f, "unit-mixed", aclFixtureOwner, id); err != nil {
				t.Fatalf("%s: owner denied on %s: %v", step, id, err)
			}
		}
	}
	assert("before grant", false)
	aclFixtureGrant(t, f, EnrollmentReadGrant, "unit-mixed", rootID, target, "grant")
	assert("granted", true)
	aclFixtureRestart(t, f)
	assert("granted, reopened", true)
	if aclFixtureHasReference(t, f, copies[0]) || !aclFixtureHasReference(t, f, followers[0]) {
		t.Fatal("a grant changed which records hold full lists")
	}
	aclFixtureGrant(t, f, EnrollmentReadRevoke, "unit-mixed", rootID, target, "revoke")
	assert("revoked", false)
	aclFixtureRestart(t, f)
	assert("revoked, reopened", false)
}

// The handoff recheck reads followers through their template: a template that loses the pin after
// the command is refused there, exactly as a record losing its own copy of the pin was.
func TestEnrollmentReadPinChecksFollowersThroughTheirTemplate(t *testing.T) {
	f := newEnrollmentFixture(t)
	rootID := aclFixtureProvision(t, f, "unit-pins")
	aclSeedRecords(t, f, rootID, "follower", 2, aclFixtureFollower(rootID))
	target := "unit-pins-member"
	grant := aclFixtureGrant(t, f, EnrollmentReadGrant, "unit-pins", rootID, target, "grant")
	entry := f.server.domain.entries[grant.Lease.LeaseID]
	check := func() error {
		f.server.forestMutex.RLock()
		defer f.server.forestMutex.RUnlock()
		return f.server.validateEnrollmentReadPinLocked(f.server.domain, entry)
	}
	if err := check(); err != nil {
		t.Fatal("current pins refused", err)
	}
	root, err := f.server.forest.GetNode(rootID)
	if err != nil {
		t.Fatal(err)
	}
	acl := root.Metadata[f.config.ACLMetadataKey].(map[string]interface{})
	templates := acl["createACLs"].(map[string]interface{})
	delete(templates["role"].(map[string]interface{})["principals"].(map[string]interface{}), target)
	if err = check(); err == nil {
		t.Fatal("pin survived its template losing the grant")
	}
}

func TestAdministrationPinsReadFollowersThroughTheirTemplate(t *testing.T) {
	f := newAdministrationFixture(t)
	input := administrationInput(f, "admin_pins_proof")
	first := f.enroll(t, input)
	enrollmentAssertAppliedPair(t, f.received(t, first), first, "applied")
	rootID := first.Lease.Binding.RootID
	aclSeedRecords(t, f, rootID, "follower", 3, func() interface{} { return domainACLReferenceValue(rootID, "role") })
	replay := func(tag string) error {
		f.mu.Lock()
		f.session = "fresh_" + tag
		f.mu.Unlock()
		input.Proof, input.RequestID = "admin_"+tag+"_proof", "admin_"+tag+"_request"
		_, err := f.server.DomainEnroll(context.Background(), input)
		return err
	}
	if err := replay("current"); err != nil {
		t.Fatal("followers of an unchanged template refused", err)
	}
	root, err := f.server.forest.GetNode(rootID)
	if err != nil {
		t.Fatal(err)
	}
	wrongKind := root.Children["follower-000"]
	wrongKind.Metadata[f.config.ACLMetadataKey] = domainACLReferenceValue(rootID, "associate")
	if err = replay("wrong-kind"); err == nil {
		t.Fatal("a follower of another kind's template passed the pins")
	}
}

// A change over followers writes the root alone, so its receipt has to say what else it reached.
func TestEnrollmentReceiptStatesTheFollowersItReached(t *testing.T) {
	f := newEnrollmentFixture(t)
	rootID := aclFixtureProvision(t, f, "unit-audit")
	follower := func(kind string) func() interface{} {
		return func() interface{} { return domainACLReferenceValue(rootID, kind) }
	}
	copies := aclSeedRecords(t, f, rootID, "copy", 2, aclFixtureCopy(t, f, rootID))
	aclSeedKind(t, f, rootID, "role", "role-follower", 3, follower("role"))
	aclSeedKind(t, f, rootID, "record", "record-follower", 4, follower("record"))
	target := "unit-audit-member"
	grant := aclFixtureGrant(t, f, EnrollmentReadGrant, "unit-audit", rootID, target, "grant")
	receipt := aclFixtureReceipt(t, f, grant)
	want := map[string]int{"role": 3, "record": 4}
	if !domainEqual(receipt.Followers, want) {
		t.Fatalf("receipt states %v, want %v", receipt.Followers, want)
	}
	if len(receipt.Targets) != 1+len(copies) {
		t.Fatalf("receipt names %d written records, want the root and %d copies", len(receipt.Targets), len(copies))
	}
	aclFixtureRestart(t, f)
	disk, err := stagedTestDisk(t, f.server).GetNode(rootID)
	if err != nil {
		t.Fatal(err)
	}
	var stored stagedReceipt
	if err = decodeStagedInternal(disk.CommandReceipts[stagedCommandKey(receipt.Command)], &stored); err != nil || !domainEqual(stored.Followers, want) {
		t.Fatalf("durable receipt states %v, %v", stored.Followers, err)
	}
	aclSeedKind(t, f, rootID, "role", "later-follower", 1, follower("role"))
	revoke := aclFixtureGrant(t, f, EnrollmentReadRevoke, "unit-audit", rootID, target, "revoke")
	if got := aclFixtureReceipt(t, f, revoke).Followers; !domainEqual(got, map[string]int{"role": 4, "record": 4}) {
		t.Fatalf("revoke counted the followers of that moment wrongly: %v", got)
	}
}

// Without followers the receipt keeps its exact old bytes, so existing receipt hashes stand.
func TestEnrollmentReceiptOverCopiesKeepsItsShape(t *testing.T) {
	f := newEnrollmentFixture(t)
	rootID := aclFixtureProvision(t, f, "unit-shape")
	aclSeedRecords(t, f, rootID, "copy", 2, aclFixtureCopy(t, f, rootID))
	target := "unit-shape-member"
	grant := aclFixtureGrant(t, f, EnrollmentReadGrant, "unit-shape", rootID, target, "grant")
	raw, err := json.Marshal(aclFixtureReceipt(t, f, grant))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "followers") {
		t.Fatalf("a receipt over copies changed shape: %s", raw)
	}
}

func TestEnrollmentFollowerStatementsAreBound(t *testing.T) {
	enrollment := stagedReceipt{Command: stagedCommand{Action: EnrollmentReadGrant}, EnrollmentRecord: json.RawMessage("{}")}
	cases := []struct {
		name    string
		mutate  func(*stagedReceipt)
		refused bool
	}{
		{"a member read change", func(r *stagedReceipt) { r.Followers = map[string]int{"role": 1} }, false},
		{"none", func(r *stagedReceipt) {}, false},
		{"a zero count", func(r *stagedReceipt) { r.Followers = map[string]int{"role": 0} }, true},
		{"a negative count", func(r *stagedReceipt) { r.Followers = map[string]int{"role": -1} }, true},
		{"an empty kind", func(r *stagedReceipt) { r.Followers = map[string]int{"": 1} }, true},
		{"a provision", func(r *stagedReceipt) {
			r.Followers, r.Command.Action = map[string]int{"role": 1}, EnrollmentProvision
		}, true},
		{"a product command", func(r *stagedReceipt) {
			r.Followers, r.EnrollmentRecord, r.Command.Action = map[string]int{"role": 1}, nil, nativeStoreCommand
		}, true},
	}
	for _, item := range cases {
		receipt := enrollment
		item.mutate(&receipt)
		if err := validateEnrollmentFollowers(receipt, 200); (err != nil) != item.refused {
			t.Fatalf("%s: %v", item.name, err)
		}
	}
}

// The check has to sit on the path every stored receipt passes, not only exist.
func TestEnrollmentFollowerStatementIsCheckedOnEveryReceipt(t *testing.T) {
	product := stagedReceipt{Command: stagedCommand{Action: nativeStoreCommand}, Followers: map[string]int{"role": 1}}
	if err := validateEnrollmentReceipt(stagedTestBinding(), product, 200); err == nil || !strings.Contains(err.Error(), "access change") {
		t.Fatal("a product receipt stated followers", err)
	}
	product.Followers = nil
	if err := validateEnrollmentReceipt(stagedTestBinding(), product, 200); err != nil {
		t.Fatal("a product receipt with no statement was refused", err)
	}
}
