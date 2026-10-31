// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"fmt"
	"testing"
)

// Three forests take the same history: the oracle, full copies on the current code, and references
// on the current code. All three must answer every access identically after every step.

const (
	aclKey        = "test.acl"
	aclOwner      = "acl-owner"
	aclAdmin      = "acl-admin"
	aclMember     = "acl-member"
	aclOtherUser  = "acl-other-member"
	aclStranger   = "acl-stranger"
	aclWriteOp    = "png.store.write.define"
	aclStoreRead  = "png.store.read"
	aclGrantRev1  = "acl-grant-1"
	aclGrantRev2  = "acl-grant-2"
	aclStaleRev   = "acl-grant-stale"
	aclForestsLen = 3
)

// "silent" has store access but no graph read profile: a grant refuses it, a revoke changes the
// record and not its template. That is the case where a follower must take a full list.
var aclKinds = map[string]string{"root": "native.root", "png_record": "native.png_record", "associate": "native.associate", "silent": "native.silent"}

func aclOwned(account, root string) DomainOwnedScope {
	store := map[string][]string{"root": {"id", "children", "data.a", "data.b", "reference"}, "png_record": {"id", "data.a", "data.b", "reference"}, "associate": {"id", "label", "reference"}, "silent": {"id", "data.a"}}
	layout := DomainLayout{Kinds: aclKinds, Profiles: map[string]map[string][]string{
		"read":       {"root": {"id", "label"}, "png_record": {"id"}, "associate": {"id", "label", "reference"}},
		aclStoreRead: store,
		aclWriteOp:   store,
	}}
	return DomainOwnedScope{Binding: stagedBinding{ProductID: "manifest", ScopeID: "scope-" + account, AccountID: account, AccountRootID: "account-" + account, RootID: root}, Bounds: stagedTestBounds(), Layout: layout}
}

func aclGrants(owned DomainOwnedScope, kind string, write bool) map[string]domainGrant {
	grants := map[string]domainGrant{}
	for _, operation := range []string{"read", aclStoreRead, aclWriteOp} {
		fields := owned.Layout.Profiles[operation][kind]
		if len(fields) == 0 || (operation == aclWriteOp && !write) {
			continue
		}
		grants[operation] = domainGrant{Fields: append([]string(nil), fields...), Reference: domainContains(fields, "reference")}
	}
	return grants
}

func aclRootValue(t *testing.T, owned DomainOwnedScope) interface{} {
	t.Helper()
	ownerGrants := aclGrants(owned, "root", true)
	ownerGrants[EnrollmentProvision] = domainGrant{Fields: []string{"acl"}}
	write := ownerGrants[aclWriteOp]
	write.CreateKinds = []string{"png_record", "associate", "silent"}
	ownerGrants[aclWriteOp] = write
	adminGrants := aclGrants(owned, "root", true)
	adminWrite := adminGrants[aclWriteOp]
	adminWrite.CreateKinds = []string{"png_record", "associate", "silent"}
	adminGrants[aclWriteOp] = adminWrite
	acl := domainACL{ContractRevision: domainACLRevision, Principals: map[string]map[string]domainGrant{aclOwner: ownerGrants, aclAdmin: adminGrants}, CreateACLs: map[string]domainACL{}}
	for _, kind := range []string{"png_record", "associate", "silent"} {
		template := domainACL{ContractRevision: domainACLRevision, Principals: map[string]map[string]domainGrant{aclOwner: aclGrants(owned, kind, true), aclAdmin: aclGrants(owned, kind, true)}}
		template.Principals[aclOwner][EnrollmentProvision] = domainGrant{Fields: []string{"acl"}}
		acl.CreateACLs[kind] = template
	}
	value, err := enrollmentACLValue(acl)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type aclMode int

const (
	aclOracle aclMode = iota
	aclCopies
	aclReferences
)

type aclForest struct {
	mode    aclMode
	d       *domainEngine
	owned   DomainOwnedScope
	records map[string]DomainRecord
}

func newACLForest(t *testing.T, mode aclMode, owned DomainOwnedScope) *aclForest {
	t.Helper()
	root := DomainRecord{ID: owned.Binding.RootID, Kind: aclKinds["root"], Metadata: map[string]interface{}{aclKey: aclRootValue(t, owned)}}
	d := &domainEngine{config: DomainConfig{ACLMetadataKey: aclKey}, policy: &domainOwnerPolicy{key: aclKey}, scopes: map[DomainScope]DomainOwnedScope{aclScope(owned): owned}}
	if mode != aclOracle {
		d.config.WorkloadPolicy = wlPolicy()
	}
	return &aclForest{mode: mode, d: d, owned: owned, records: map[string]DomainRecord{root.ID: root}}
}

func aclScope(owned DomainOwnedScope) DomainScope {
	return DomainScope{AccountID: owned.Binding.AccountID, Product: owned.Binding.ProductID}
}

func (f *aclForest) root() DomainRecord { return f.records[f.owned.Binding.RootID] }
func (f *aclForest) view() DomainView {
	return DomainView{Binding: f.owned.Binding, Records: f.records, ACLMetadataKey: aclKey}
}

func (f *aclForest) create(t *testing.T, id, kind string) {
	t.Helper()
	actor := DomainVerified{PrincipalID: aclAdmin}
	policy := &domainOwnerPolicy{key: aclKey}
	var value interface{}
	var err error
	if f.mode == aclReferences {
		value, err = policy.CreateACLLocked(actor, aclWriteOp, kind, f.root())
	} else {
		value, err = legacyCreateACL(policy, actor, aclWriteOp, kind, f.root())
	}
	if err != nil {
		t.Fatal(err)
	}
	f.records[id] = DomainRecord{ID: id, Kind: aclKinds[kind], Metadata: map[string]interface{}{aclKey: value, "label": "LABELLED " + id}}
}

func aclEnrollmentEntry(owned DomainOwnedScope, operation, target, revision string) *domainEntry {
	return &domainEntry{owned: owned, enrollment: &enrollmentEntry{actor: EnrollmentVerified{Request: EnrollmentRequest{Operation: operation, TargetPrincipalID: &target}, PrincipalReference: &DomainPrincipalReference{TargetGrantRevision: &revision}}}}
}

// Returns the error text so the three forests can be compared on refusals too.
func (f *aclForest) readChange(operation, target, revision string) string {
	entry := aclEnrollmentEntry(f.owned, operation, target, revision)
	writes := []stagedWrite{}
	current := newEnrollmentACLWrites(f.d, entry, f.root())
	for _, record := range f.records {
		write, err := f.changeOne(entry, current, record)
		if err != nil {
			return err.Error()
		}
		if write != nil {
			writes = append(writes, *write)
		}
	}
	for _, write := range writes {
		f.records[write.NodeID].Metadata[write.Key] = write.Value
	}
	return ""
}

func (f *aclForest) changeOne(entry *domainEntry, current *enrollmentACLWrites, record DomainRecord) (*stagedWrite, error) {
	if f.mode == aclOracle {
		return legacyEnrollmentACLWrite(f.d, entry, record)
	}
	return current.of(record)
}

type aclActor struct {
	label string
	actor DomainVerified
}

func aclActors(scope DomainScope) []aclActor {
	human := func(principal, revision string) DomainVerified {
		return DomainVerified{PrincipalID: principal, Kind: "human", GrantRevision: revision, ExpiresAt: domainNow() + 300, Scope: scope}
	}
	expired := human(aclAdmin, aclGrantRev1)
	expired.ExpiresAt = domainNow() - 1
	integration := human(aclAdmin, aclGrantRev1)
	integration.Kind = "integration_actor"
	actors := []aclActor{{"expired-admin", expired}, {"bare-integration-admin", integration}}
	for _, principal := range []string{aclOwner, aclAdmin, aclStranger} {
		actors = append(actors, aclActor{principal, human(principal, aclGrantRev1)})
	}
	for _, principal := range []string{aclMember, aclOtherUser} {
		for _, revision := range []string{aclGrantRev1, aclGrantRev2, aclStaleRev} {
			actors = append(actors, aclActor{principal + "@" + revision, human(principal, revision)})
		}
	}
	return actors
}

var aclFieldSets = [][]string{nil, {"id"}, {"label"}, {"children"}, {"data.a"}, {"data.b"}, {"reference"}, {"acl"}, {"id", "data.a"}, {"id", "data.a", "data.b"}, {"id", "reference"}, {"id", "not.a.field"}, {"id", "label", "reference"}}

// One line per access; Reference follows the requested fields exactly as authorizeIntentLocked sets it.
func (f *aclForest) decisions() map[string]string {
	result := map[string]string{}
	for id, record := range f.records {
		for _, who := range aclActors(aclScope(f.owned)) {
			f.decideActor(result, id, record, who)
		}
	}
	return result
}

func (f *aclForest) decideActor(result map[string]string, id string, record DomainRecord, who aclActor) {
	for _, operation := range []string{"read", aclStoreRead, aclWriteOp, EnrollmentProvision, "unknown.operation"} {
		f.decideFields(result, id, record, who, operation)
		f.decideCreates(result, id, record, who, operation)
	}
}

func (f *aclForest) decideFields(result map[string]string, id string, record DomainRecord, who aclActor, operation string) {
	for _, fields := range aclFieldSets {
		access := DomainAccess{Operation: operation, Fields: fields, Reference: domainContains(fields, "reference")}
		f.decideOne(result, id, record, who, access)
	}
}

func (f *aclForest) decideCreates(result map[string]string, id string, record DomainRecord, who aclActor, operation string) {
	for _, kind := range []string{"png_record", "associate", "silent", "root"} {
		access := DomainAccess{Operation: operation, Kind: kind, Fields: []string{"id"}, Create: true}
		f.decideOne(result, id, record, who, access)
	}
}

func (f *aclForest) decideOne(result map[string]string, id string, record DomainRecord, who aclActor, access DomainAccess) {
	label := fmt.Sprintf("%s|%s|%s|%v|%s", id, who.label, access.Operation, access.Fields, access.Kind)
	result[label] = aclDecisionText(f.decide(who.actor, access, record))
}

// The oracle decides with the frozen policy. The other forests decide with the current code, with a
// workload policy configured and no workload granted, so that combination is what must not differ.
func (f *aclForest) decide(actor DomainVerified, access DomainAccess, record DomainRecord) error {
	if f.mode != aclOracle {
		return f.d.authorizeDomainRecord(actor, access, f.view(), record)
	}
	copy, err := f.d.domainPolicyRecord(actor, record)
	if err != nil {
		return err
	}
	return legacyAuthorizeLocked(&domainOwnerPolicy{key: aclKey}, actor, access, copy)
}

func aclDecisionText(err error) string {
	if err == nil {
		return "allow"
	}
	return err.Error()
}

func aclCompare(t *testing.T, step string, forests []*aclForest) {
	t.Helper()
	oracle := forests[0].decisions()
	allowed := 0
	for _, decision := range oracle {
		if decision == "allow" {
			allowed++
		}
	}
	if allowed == 0 || allowed == len(oracle) {
		t.Fatalf("%s: matrix is degenerate: %d of %d allowed", step, allowed, len(oracle))
	}
	for _, forest := range forests[1:] {
		aclCompareForest(t, step, forest, oracle)
	}
	t.Logf("%s: %d accesses identical, %d allowed", step, len(oracle), allowed)
}

func aclCompareForest(t *testing.T, step string, forest *aclForest, oracle map[string]string) {
	t.Helper()
	actual := forest.decisions()
	if len(actual) != len(oracle) {
		t.Fatalf("%s: mode %d decided %d accesses, oracle %d", step, forest.mode, len(actual), len(oracle))
	}
	for label, decision := range oracle {
		if actual[label] != decision {
			t.Fatalf("%s: mode %d %s: %q, oracle %q", step, forest.mode, label, actual[label], decision)
		}
	}
}

type aclHistory struct {
	t       *testing.T
	forests []*aclForest
	next    int
}

func newACLHistory(t *testing.T) *aclHistory {
	owned := aclOwned("acl-account", "acl-root")
	forests := make([]*aclForest, 0, aclForestsLen)
	for _, mode := range []aclMode{aclOracle, aclCopies, aclReferences} {
		forests = append(forests, newACLForest(t, mode, owned))
	}
	return &aclHistory{t: t, forests: forests}
}

func (h *aclHistory) createAll(kinds ...string) {
	for _, kind := range kinds {
		h.next++
		id := fmt.Sprintf("record-%03d", h.next)
		for _, forest := range h.forests {
			forest.create(h.t, id, kind)
		}
	}
}

func (h *aclHistory) change(step, operation, target, revision string) {
	h.t.Helper()
	outcomes := make([]string, len(h.forests))
	for index, forest := range h.forests {
		outcomes[index] = forest.readChange(operation, target, revision)
		if outcomes[index] != outcomes[0] {
			h.t.Fatalf("%s: mode %d change %q, oracle %q", step, forest.mode, outcomes[index], outcomes[0])
		}
	}
	h.t.Logf("%s: change outcome %q", step, outcomes[0])
	aclCompare(h.t, step, h.forests)
}

// Copies on the current code must also match the oracle byte for byte: that is the existing forest.
func (h *aclHistory) assertCopiesUnchanged() {
	h.t.Helper()
	oracle, copies := h.forests[0], h.forests[1]
	for id, record := range oracle.records {
		left, _ := CanonicalDomainJSON(record.Metadata[aclKey])
		right, _ := CanonicalDomainJSON(copies.records[id].Metadata[aclKey])
		if !bytes.Equal(left, right) {
			h.t.Fatalf("existing copy diverged on %s", id)
		}
	}
}

func TestDomainACLReferencesDecideExactlyAsCopiesAcrossHistory(t *testing.T) {
	h := newACLHistory(t)
	h.createAll("png_record", "png_record", "associate")
	aclCompare(t, "fresh", h.forests)
	h.change("grant member, silent records absent", EnrollmentReadGrant, aclMember, aclGrantRev1)
	h.createAll("png_record", "associate")
	aclCompare(t, "records created after a grant", h.forests)
	h.change("grant second member", EnrollmentReadGrant, aclOtherUser, aclGrantRev2)
	h.createAll("png_record")
	h.change("regrant member with a new revision", EnrollmentReadGrant, aclMember, aclGrantRev2)
	h.change("revoke member", EnrollmentReadRevoke, aclMember, aclGrantRev2)
	h.createAll("png_record", "associate")
	aclCompare(t, "records created after a revoke", h.forests)
	h.change("revoke member again", EnrollmentReadRevoke, aclMember, aclGrantRev2)
	h.change("owner cannot be changed", EnrollmentReadGrant, aclOwner, aclGrantRev1)
	h.change("owner cannot be revoked", EnrollmentReadRevoke, aclOwner, aclGrantRev1)
	h.createAll("silent", "silent")
	aclCompare(t, "kind without a read profile", h.forests)
	h.change("grant refused by a kind without a read profile", EnrollmentReadGrant, aclMember, aclGrantRev1)
	h.change("revoke administrator store read, template keeps it", EnrollmentReadRevoke, aclAdmin, aclGrantRev1)
	h.createAll("silent", "png_record")
	aclCompare(t, "records created after the divergence", h.forests)
	h.assertCopiesUnchanged()
}

func TestDomainACLReferenceHistoryRewritesOnlyWhatDiffers(t *testing.T) {
	h := newACLHistory(t)
	h.createAll("png_record", "png_record", "png_record", "associate")
	references := h.forests[2]
	entry := aclEnrollmentEntry(references.owned, EnrollmentReadGrant, aclMember, aclGrantRev1)
	writes := newEnrollmentACLWrites(references.d, entry, references.root())
	for id, record := range references.records {
		write, err := writes.of(record)
		if err != nil {
			t.Fatal(err)
		}
		if (write != nil) != (id == references.owned.Binding.RootID) {
			t.Fatalf("only the root takes a write here, not %s", id)
		}
	}
	h.createAll("silent")
	h.change("revoke administrator store read", EnrollmentReadRevoke, aclAdmin, aclGrantRev1)
	silent := references.records[fmt.Sprintf("record-%03d", h.next)]
	if _, isReference, _ := domainACLReferenceOf(silent.Metadata[aclKey]); isReference {
		t.Fatal("a record whose list left the template must hold the full list")
	}
	follower := references.records["record-001"]
	if _, isReference, _ := domainACLReferenceOf(follower.Metadata[aclKey]); !isReference {
		t.Fatal("the png_record template changes the same way, so its records keep following it")
	}
}

// Records that took a full list are written, so Targets names them; only followers are counted.
func TestEnrollmentFollowerCountsLeaveOutRecordsThatTookAList(t *testing.T) {
	h := newACLHistory(t)
	h.createAll("png_record", "png_record", "associate", "silent")
	references := h.forests[2]
	entry := aclEnrollmentEntry(references.owned, EnrollmentReadRevoke, aclAdmin, aclGrantRev1)
	writes := newEnrollmentACLWrites(references.d, entry, references.root())
	written := []string{}
	for id, record := range references.records {
		write, err := writes.of(record)
		if err != nil {
			t.Fatal(err)
		}
		if write != nil {
			written = append(written, id)
		}
	}
	if !domainEqual(writes.followers, map[string]int{"png_record": 2, "associate": 1}) {
		t.Fatalf("followers %v", writes.followers)
	}
	if len(written) != 2 {
		t.Fatalf("expected the root and the silent record written, got %v", written)
	}
}

// A grant change on one record: the record holds its own list from then on and stays correct
// through later changes, in all three forests.
func TestDomainACLRecordOverrideStaysCorrectAndIndependent(t *testing.T) {
	h := newACLHistory(t)
	h.createAll("png_record", "png_record", "associate")
	override := domainACL{ContractRevision: domainACLRevision, Principals: map[string]map[string]domainGrant{aclOwner: {aclStoreRead: {Fields: []string{"id"}}}, aclStranger: {aclStoreRead: {Fields: []string{"id", "data.a"}, TargetGrantRevision: aclGrantRev1}}}}
	value, err := enrollmentACLValue(override)
	if err != nil {
		t.Fatal(err)
	}
	for _, forest := range h.forests {
		forest.records["record-001"].Metadata[aclKey] = value
	}
	aclCompare(t, "one record overridden", h.forests)
	h.change("grant member after override", EnrollmentReadGrant, aclMember, aclGrantRev1)
	h.change("revoke member after override", EnrollmentReadRevoke, aclMember, aclGrantRev1)
	h.change("grant the override's own principal", EnrollmentReadGrant, aclStranger, aclGrantRev2)
	if _, isReference, _ := domainACLReferenceOf(h.forests[2].records["record-001"].Metadata[aclKey]); isReference {
		t.Fatal("override became a reference")
	}
	h.assertCopiesUnchanged()
}

func TestDomainACLGrantReferenceFlagIsDecidedByItsField(t *testing.T) {
	owned := aclOwned("acl-account", "acl-root")
	forest := newACLForest(t, aclCopies, owned)
	with := domainACL{ContractRevision: domainACLRevision, Principals: map[string]map[string]domainGrant{aclMember: {"read": {Fields: []string{"id"}, Reference: true}}}}
	without := domainACL{ContractRevision: domainACLRevision, Principals: map[string]map[string]domainGrant{aclMember: {"read": {Fields: []string{"id"}}}}}
	if !domainACLDecisionsEqual(with, without) {
		t.Fatal("a flag on a grant without the reference field must not change decisions")
	}
	with.Principals[aclMember]["read"] = domainGrant{Fields: []string{"id", "reference"}, Reference: true}
	without.Principals[aclMember]["read"] = domainGrant{Fields: []string{"id", "reference"}}
	if domainACLDecisionsEqual(with, without) {
		t.Fatal("a flag on a grant listing the reference field decides reference access")
	}
	actor := DomainVerified{PrincipalID: aclMember, Kind: "human", ExpiresAt: domainNow() + 30, Scope: aclScope(owned)}
	for _, value := range []domainACL{with, without} {
		encoded, _ := enrollmentACLValue(value)
		record := DomainRecord{ID: "r", Kind: aclKinds["png_record"], Metadata: map[string]interface{}{aclKey: encoded}}
		err := forest.d.authorizeDomainRecord(actor, DomainAccess{Operation: "read", Fields: []string{"id", "reference"}, Reference: true}, forest.view(), record)
		if (err == nil) != value.Principals[aclMember]["read"].Reference {
			t.Fatal("reference access must follow the flag once its field is granted", err)
		}
	}
}

// Who may create what is decided before any record exists, on the root, for both shapes.
func TestDomainACLCreationDecidesExactlyAsCopies(t *testing.T) {
	forest := newACLForest(t, aclReferences, aclOwned("acl-account", "acl-root"))
	checked, allowed := 0, 0
	for _, who := range aclActors(aclScope(forest.owned)) {
		for _, operation := range []string{"read", aclStoreRead, aclWriteOp, "unknown.operation"} {
			count, granted := aclCompareCreation(t, forest, who, operation)
			checked, allowed = checked+count, allowed+granted
		}
	}
	if allowed == 0 || allowed == checked {
		t.Fatalf("creation matrix is degenerate: %d of %d", allowed, checked)
	}
}

func aclCompareCreation(t *testing.T, forest *aclForest, who aclActor, operation string) (int, int) {
	t.Helper()
	policy := &domainOwnerPolicy{key: aclKey}
	kinds, allowed := []string{"png_record", "associate", "silent", "root", "absent"}, 0
	for _, kind := range kinds {
		_, legacy := legacyCreateACL(policy, who.actor, operation, kind, forest.root())
		value, current := policy.CreateACLLocked(who.actor, operation, kind, forest.root())
		if aclDecisionText(legacy) != aclDecisionText(current) {
			t.Fatalf("%s %s %s: %v, oracle %v", who.label, operation, kind, current, legacy)
		}
		if current != nil {
			continue
		}
		allowed++
		if _, isReference, err := domainACLReferenceOf(value); !isReference || err != nil {
			t.Fatal("a new record's list is not a reference", err)
		}
	}
	return len(kinds), allowed
}
