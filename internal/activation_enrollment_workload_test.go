// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"strings"
	"testing"
)

const wlAccount = "unit-wl-account"

type wlForest struct {
	f      *enrollmentFixture
	rootID string
}

// Every shape a record can be in: following the template or holding a copy, in and out of the
// families, of the store's kind or another. The seeds are what an import or an old engine left.
func newWLForest(t *testing.T) wlForest {
	t.Helper()
	f := newWorkloadFixture(t)
	rootID := aclFixtureProvision(t, f, wlAccount)
	follower := domainACLReferenceValue(rootID, "png_record")
	wlSeed(t, f, rootID, "follower-message", wlMessages, follower)
	wlSeed(t, f, rootID, "follower-job", wlOtherFamily, follower)
	wlSeed(t, f, rootID, "copy-message", wlMessages, wlTemplateCopy(t, f, rootID))
	wlSeed(t, f, rootID, "copy-contact", wlContacts, wlTemplateCopy(t, f, rootID))
	wlSeed(t, f, rootID, "copy-job", wlOtherFamily, wlTemplateCopy(t, f, rootID))
	aclSeedKind(t, f, rootID, "role", "role-follower", 1, func() interface{} { return domainACLReferenceValue(rootID, "role") })
	return wlForest{f, rootID}
}

var wlRecordIDs = []string{"follower-message", "follower-job", "copy-message", "copy-contact", "copy-job", "role-follower-000"}

// Which records take the workload's grant at all, stated here and not derived from the code.
func (w wlForest) holds(id string) bool {
	switch id {
	case w.rootID, "follower-message", "follower-job", "copy-message", "copy-contact":
		return true
	}
	return false
}

func wlFieldSets() [][]string {
	base := []string{"id", "pngKey", "pngFamily", "pngData", "pngVersion"}
	listed := append(append([]string{}, base...), "family."+wlMessages, "family."+wlConversations, "family."+wlContacts, "data.id", "data.account_id", "data.text", "data.direction", "data.title", "data.unread_count", "data.phone")
	return [][]string{nil, {"id"}, base, listed, {"family." + wlMessages}, {"family." + wlConversations}, {"family." + wlContacts}, {"data.text"}, {"data.phone"},
		{"family." + wlOtherFamily}, {"data.salary"}, {"data.not_listed"}, {"id", "family." + wlOtherFamily}, {"id", "data.salary"}, {"acl"}, {"ownerAcl"}, {"label"}, {"accountId"}, {"roleIds"}, {"reference"}, {"id", "reference"}, {"children"}}
}

// The whole list, written out: what a workload may touch on a record that holds its grant.
func wlAllowedField(field string, onRoot, write bool) bool {
	switch field {
	case "id", "pngKey", "pngFamily", "pngData", "pngVersion", "family." + wlMessages, "family." + wlConversations, "family." + wlContacts, "data.id", "data.account_id", "data.text", "data.direction", "data.title", "data.unread_count", "data.phone":
		return true
	case "children":
		return onRoot && write
	}
	return false
}

func (w wlForest) expected(id, operation string, fields []string, create string) bool {
	write := operation == nativeStoreCommand
	if !w.holds(id) || (operation != domainStoreReadOperation && !write) || len(fields) == 0 {
		return false
	}
	for _, field := range fields {
		if !wlAllowedField(field, id == w.rootID, write) {
			return false
		}
	}
	return create == "" || create == "png_record" && write && id == w.rootID
}

type wlTally struct{ checked, allowed int }

func (w wlForest) assertMatrix(t *testing.T, step string, actor DomainVerified, granted bool) wlTally {
	t.Helper()
	tally := wlTally{}
	for _, id := range append([]string{w.rootID}, wlRecordIDs...) {
		for _, operation := range []string{domainStoreReadOperation, nativeStoreCommand, "read", "role.define", EnrollmentProvision, EnrollmentReadGrant, EnrollmentWorkloadGrant, "unknown.operation"} {
			w.assertOperation(t, step, actor, granted, id, operation, &tally)
		}
	}
	return tally
}

func (w wlForest) assertOperation(t *testing.T, step string, actor DomainVerified, granted bool, id, operation string, tally *wlTally) {
	t.Helper()
	for _, fields := range wlFieldSets() {
		for _, create := range []string{"", "png_record", "associate", "root"} {
			access := DomainAccess{Operation: operation, Fields: fields, Kind: create, Create: create != "", Reference: domainContains(fields, "reference")}
			err := wlDecide(t, w.f, actor, access, id)
			want := granted && w.expected(id, operation, fields, create)
			if (err == nil) != want {
				t.Fatalf("%s: %s %s %v create=%q: decided %v, want allowed=%v", step, id, operation, fields, create, err, want)
			}
			tally.checked++
			if err == nil {
				tally.allowed++
			}
		}
	}
}

func TestWorkloadDoesExactlyItsListAcrossGrantRegrantAndRevoke(t *testing.T) {
	w := newWLForest(t)
	current := wlActor(w.f, wlAccount, wlRevision)
	other := current
	other.PrincipalID, other.SessionID = "workload:another", "workload-session:another:run-1"
	stale := wlActor(w.f, wlAccount, "unit-stale-revision")
	if tally := w.assertMatrix(t, "before any grant", current, false); tally.allowed != 0 {
		t.Fatalf("allowed %d before any grant", tally.allowed)
	}
	wlEnroll(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "grant")
	tally := w.assertMatrix(t, "granted", current, true)
	if tally.allowed == 0 || tally.allowed == tally.checked {
		t.Fatalf("matrix is degenerate: %+v", tally)
	}
	t.Logf("granted: %d accesses checked, %d allowed", tally.checked, tally.allowed)
	w.assertMatrix(t, "stale revision", stale, false)
	w.assertMatrix(t, "another workload", other, false)
	w.f.mu.Lock()
	w.f.targetRevision = wlNewRevision
	w.f.mu.Unlock()
	wlEnroll(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "regrant")
	w.assertMatrix(t, "the old revision after a regrant", current, false)
	w.assertMatrix(t, "the new revision", wlActor(w.f, wlAccount, wlNewRevision), true)
	aclFixtureRestart(t, w.f)
	w.assertMatrix(t, "the new revision, reopened", wlActor(w.f, wlAccount, wlNewRevision), true)
	w.f.mu.Lock()
	w.f.targetState = "revoked"
	w.f.mu.Unlock()
	wlEnroll(t, w.f, EnrollmentWorkloadRevoke, wlAccount, w.rootID, wlPrincipal, "revoke")
	w.assertMatrix(t, "revoked", wlActor(w.f, wlAccount, wlNewRevision), false)
	aclFixtureRestart(t, w.f)
	w.assertMatrix(t, "revoked, reopened", wlActor(w.f, wlAccount, wlNewRevision), false)
}

func TestWorkloadGrantInOneAccountReachesNoOther(t *testing.T) {
	w := newWLForest(t)
	otherRoot := aclFixtureProvision(t, w.f, "unit-wl-other-account")
	wlSeed(t, w.f, otherRoot, "other-message", wlMessages, domainACLReferenceValue(otherRoot, "png_record"))
	wlEnroll(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "grant")
	foreign := wlActor(w.f, "unit-wl-other-account", wlRevision)
	access := wlStoreAccess(nativeStoreCommand, wlMessages)
	for _, id := range []string{otherRoot, "other-message"} {
		if err := wlDecide(t, w.f, foreign, access, id); err == nil {
			t.Fatalf("a grant in one account opened %s in another", id)
		}
	}
	foreign.Intent = DomainIntent{Fields: []DomainFieldSet{{Resource: DomainResource{ResourceID: w.rootID}, Fields: []string{"id"}}}}
	d := w.f.server.domain
	w.f.server.forestMutex.RLock()
	defer w.f.server.forestMutex.RUnlock()
	view, err := w.f.server.domainScopeViewLocked(d.scopes[foreign.Scope], false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.authorizeIntentLocked(foreign, view); err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatal("another account's root reached evaluation", err)
	}
}

func TestWorkloadGrantWritesOnlyWhatMustHoldIt(t *testing.T) {
	w := newWLForest(t)
	grant := wlEnroll(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "grant")
	receipt := aclFixtureReceipt(t, w.f, grant)
	written := map[string]bool{}
	for _, target := range receipt.Targets {
		written[target.NodeID] = true
	}
	if len(written) != 3 || !written[w.rootID] || !written["copy-message"] || !written["copy-contact"] {
		t.Fatalf("grant wrote %v", written)
	}
	if !domainEqual(receipt.Followers, map[string]int{"png_record": 2}) {
		t.Fatalf("followers %v", receipt.Followers)
	}
	if aclFixtureHasReference(t, w.f, "copy-job") || !aclFixtureHasReference(t, w.f, "follower-message") {
		t.Fatal("a grant changed which records hold full lists")
	}
	acl := wlRootACL(t, w.f, w.rootID)
	write := acl.Principals[wlPrincipal][nativeStoreCommand]
	if !domainEqual(write.CreateKinds, []string{"png_record"}) || write.Reference || domainContains(write.Fields, "reference") {
		t.Fatalf("root grant wider than its list: %+v", write)
	}
	if _, listed := acl.CreateACLs["role"].Principals[wlPrincipal]; listed {
		t.Fatal("another kind's template took the grant")
	}
	if len(acl.Principals[wlPrincipal]) != 2 {
		t.Fatalf("root grant has operations %v", acl.Principals[wlPrincipal])
	}
}

func TestWorkloadControlsAreAttributedInTheirReceipts(t *testing.T) {
	w := newWLForest(t)
	grant := aclFixtureReceipt(t, w.f, wlEnroll(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "grant"))
	var record enrollmentRecordValue
	if err := json.Unmarshal(grant.EnrollmentRecord, &record); err != nil {
		t.Fatal(err)
	}
	if grant.Command.PrincipalID != aclFixtureOwner || grant.Command.Action != EnrollmentWorkloadGrant || record.Request.TargetPrincipalID == nil || *record.Request.TargetPrincipalID != wlPrincipal {
		t.Fatalf("grant receipt attribution: %+v", grant.Command)
	}
	if record.TargetGrantRevision == nil || *record.TargetGrantRevision != wlRevision {
		t.Fatal("grant receipt lost the revision it granted")
	}
}

func TestWorkloadRevokeLeavesNoTraceOfItsGrant(t *testing.T) {
	w := newWLForest(t)
	wlEnroll(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "grant")
	revoke := aclFixtureReceipt(t, w.f, wlEnroll(t, w.f, EnrollmentWorkloadRevoke, wlAccount, w.rootID, wlPrincipal, "revoke"))
	if len(revoke.Targets) != 3 || !domainEqual(revoke.Followers, map[string]int{"png_record": 2}) {
		t.Fatalf("revoke wrote %v, followers %v", revoke.Targets, revoke.Followers)
	}
	acl := wlRootACL(t, w.f, w.rootID)
	if _, listed := acl.Principals[wlPrincipal]; listed {
		t.Fatal("root kept the grant")
	}
	if _, listed := acl.CreateACLs["png_record"].Principals[wlPrincipal]; listed {
		t.Fatal("template kept the grant")
	}
	node, err := w.f.server.forest.GetNode("copy-message")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(node.Metadata[w.f.config.ACLMetadataKey])
	if strings.Contains(string(raw), wlPrincipal) {
		t.Fatal("a copy kept the grant")
	}
}

func TestWorkloadControlsRefused(t *testing.T) {
	cases := []struct {
		name, operation, target, corrupt string
	}{
		{"a workload granting", EnrollmentWorkloadGrant, "workload:another", "workload-kind"},
		{"a workload's own issuer", EnrollmentWorkloadGrant, "workload:another", "workload-issuer"},
		{"a workload revoking", EnrollmentWorkloadRevoke, wlPrincipal, "workload-kind"},
		{"a workload granting a member read", EnrollmentReadGrant, "unit-member", "workload-kind"},
		{"a person under a workload principal", EnrollmentWorkloadGrant, "workload:another", "workload-principal"},
		{"a person in a workload session", EnrollmentWorkloadGrant, "workload:another", "workload-session"},
		{"a person who is not the owner", EnrollmentWorkloadGrant, wlPrincipal, "another-person"},
		{"a workload grant to a person", EnrollmentWorkloadGrant, "unit-member", ""},
		{"a workload grant to a bare prefix", EnrollmentWorkloadGrant, "workload:", ""},
		{"a workload grant to an upper-case form", EnrollmentWorkloadGrant, "workload:ALIVE5", ""},
		{"a workload grant to a dressed form", EnrollmentWorkloadGrant, "WORKLOAD:alive5", ""},
		{"a member read to a workload", EnrollmentReadGrant, wlPrincipal, ""},
		{"a member read to a dressed workload", EnrollmentReadGrant, "Workload:alive5", ""},
		{"a member revoke naming a workload", EnrollmentReadRevoke, wlPrincipal, ""},
	}
	for _, item := range cases {
		w := newWLForest(t)
		w.f.mu.Lock()
		w.f.corrupt = item.corrupt
		w.f.mu.Unlock()
		before := enrollmentCurrentRevision(t, w.f, w.rootID)
		err := wlEnrollRefused(t, w.f, item.operation, wlAccount, w.rootID, item.target, "refused")
		if after := enrollmentCurrentRevision(t, w.f, w.rootID); after != before {
			t.Fatalf("%s changed the forest: %v", item.name, err)
		}
	}
}

func TestWorkloadControlRefusedWithoutItsPolicy(t *testing.T) {
	config := wlFixtureConfig(t)
	config.WorkloadPolicy = nil
	f := newEnrollmentFixtureWith(t, config)
	rootID := aclFixtureProvision(t, f, wlAccount)
	wlEnrollRefused(t, f, EnrollmentWorkloadGrant, wlAccount, rootID, wlPrincipal, "no-policy")
}

func TestWorkloadRevokeCarriesARevokedTarget(t *testing.T) {
	w := newWLForest(t)
	wlEnroll(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "grant")
	w.f.mu.Lock()
	w.f.targetState = "revoked"
	w.f.mu.Unlock()
	wlEnrollRefused(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "regrant-revoked")
	wlEnroll(t, w.f, EnrollmentWorkloadRevoke, wlAccount, w.rootID, wlPrincipal, "revoke")
}

func TestWorkloadGrantAboveTheChangeBound(t *testing.T) {
	w := newWLForest(t)
	aclSeedRecordsAsStore(t, w, "more-follower", stagedTestBounds().MaxChanges, domainACLReferenceValue(w.rootID, "png_record"))
	grant := aclFixtureReceipt(t, w.f, wlEnroll(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "grant"))
	if grant.Followers["png_record"] != stagedTestBounds().MaxChanges+2 {
		t.Fatalf("followers %v", grant.Followers)
	}
	copies := newWLForest(t)
	aclSeedRecordsAsStore(t, copies, "more-copy", stagedTestBounds().MaxChanges, wlTemplateCopy(t, copies.f, copies.rootID))
	if err := wlEnrollRefused(t, copies.f, EnrollmentWorkloadGrant, wlAccount, copies.rootID, wlPrincipal, "grant"); !strings.Contains(err.Error(), "exceeds change bound") {
		t.Fatal("copies must keep their bound", err)
	}
}

func aclSeedRecordsAsStore(t *testing.T, w wlForest, prefix string, count int, value interface{}) {
	t.Helper()
	for index := 0; index < count; index++ {
		wlSeed(t, w.f, w.rootID, wlDescribeID(prefix, index), wlMessages, value)
	}
}

func wlDescribeID(prefix string, index int) string {
	return prefix + "-" + strings.Repeat("x", index%3) + string(rune('a'+index%26)) + string(rune('a'+index/26))
}

func TestWorkloadPinChecksRootTemplateAndCopies(t *testing.T) {
	for _, damage := range []string{"root", "template", "copy"} {
		w := newWLForest(t)
		begin := wlEnroll(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "grant")
		entry := w.f.server.domain.entries[begin.Lease.LeaseID]
		check := func() error {
			w.f.server.forestMutex.RLock()
			defer w.f.server.forestMutex.RUnlock()
			return w.f.server.validateEnrollmentCurrentLocked(w.f.server.domain, entry)
		}
		if err := check(); err != nil {
			t.Fatal("current pins refused", err)
		}
		w.damage(t, damage)
		if err := check(); err == nil {
			t.Fatalf("pin survived losing the grant on the %s", damage)
		}
	}
}

func (w wlForest) damage(t *testing.T, where string) {
	t.Helper()
	root, err := w.f.server.forest.GetNode(w.rootID)
	if err != nil {
		t.Fatal(err)
	}
	key := w.f.config.ACLMetadataKey
	acl := root.Metadata[key].(map[string]interface{})
	switch where {
	case "root":
		delete(acl["principals"].(map[string]interface{}), wlPrincipal)
	case "template":
		template := acl["createACLs"].(map[string]interface{})["png_record"].(map[string]interface{})
		delete(template["principals"].(map[string]interface{}), wlPrincipal)
	case "copy":
		list := root.Children["copy-message"].Metadata[key].(map[string]interface{})
		delete(list["principals"].(map[string]interface{}), wlPrincipal)
	}
}

// A replay is the same command from the same person about the same grant, or it is refused.
func TestWorkloadGrantReplayBindsItsRevision(t *testing.T) {
	w := newWLForest(t)
	revision := enrollmentCurrentRevision(t, w.f, w.rootID)
	target := wlPrincipal
	first := w.f.enroll(t, w.f.input(EnrollmentWorkloadGrant, wlAccount, "unit-stable", "unit-proof-first", revision, &target))
	enrollmentAssertAppliedPair(t, w.f.received(t, first), first, "applied")
	again := w.f.enroll(t, w.f.input(EnrollmentWorkloadGrant, wlAccount, "unit-stable", "unit-proof-again", revision, &target))
	enrollmentAssertAppliedPair(t, w.f.received(t, again), again, "replayed")
	w.f.mu.Lock()
	w.f.targetRevision = wlNewRevision
	w.f.mu.Unlock()
	raw, err := CanonicalDomainJSON(w.f.input(EnrollmentWorkloadGrant, wlAccount, "unit-stable", "unit-proof-changed", revision, &target))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.f.server.DomainEnrollJSON(contextBackground(), raw); err == nil {
		t.Fatal("a replay carried another grant revision")
	}
}

// A list naming a workload cannot give it more than its list, whoever wrote that list.
func TestWorkloadHeldToItsListWhateverAnAccessListSays(t *testing.T) {
	wide := domainGrant{Fields: []string{"id", "acl", "ownerAcl", "reference", "label", "family." + wlOtherFamily, "data.salary"}, CreateKinds: []string{"associate", "role", "png_record"}, Reference: true}
	list := domainACL{ContractRevision: domainACLRevision, Principals: map[string]map[string]domainGrant{wlPrincipal: {nativeStoreCommand: wide, domainStoreReadOperation: wide, "role.define": wide, EnrollmentReadGrant: wide, EnrollmentProvision: wide}}}
	value, err := enrollmentACLValue(list)
	if err != nil {
		t.Fatal(err)
	}
	record := DomainRecord{ID: "r", Kind: "native.png_record", Metadata: map[string]interface{}{aclKey: value}}
	policy := &domainOwnerPolicy{key: aclKey, workload: wlPolicy()}
	actor := DomainVerified{PrincipalID: wlPrincipal, Kind: domainWorkloadKind, SessionID: wlSession, ExpiresAt: domainNow() + 30}
	refused := []DomainAccess{
		{Operation: "role.define", Fields: []string{"id"}},
		{Operation: EnrollmentReadGrant, Fields: []string{"acl"}},
		{Operation: EnrollmentProvision, Fields: []string{"acl"}},
		{Operation: nativeStoreCommand, Fields: []string{"acl"}},
		{Operation: nativeStoreCommand, Fields: []string{"ownerAcl"}},
		{Operation: nativeStoreCommand, Fields: []string{"label"}},
		{Operation: nativeStoreCommand, Fields: []string{"family." + wlOtherFamily}},
		{Operation: domainStoreReadOperation, Fields: []string{"family." + wlOtherFamily}},
		{Operation: nativeStoreCommand, Fields: []string{"data.salary"}},
		{Operation: nativeStoreCommand, Fields: []string{"id", "reference"}, Reference: true},
		{Operation: nativeStoreCommand, Fields: []string{"id"}, Reference: true},
		{Operation: nativeStoreCommand, Fields: []string{"id"}, Create: true, Kind: "associate"},
		{Operation: nativeStoreCommand, Fields: []string{"id"}, Create: true, Kind: "role"},
	}
	for _, access := range refused {
		if err = policy.AuthorizeLocked(actor, access, record); err == nil {
			t.Fatalf("a list widened the workload: %+v", access)
		}
	}
	if err = policy.AuthorizeLocked(actor, DomainAccess{Operation: nativeStoreCommand, Fields: []string{"id"}, Create: true, Kind: "png_record"}, record); err != nil {
		t.Fatal("the policy guard refused its own list", err)
	}
	bare := actor
	bare.PrincipalID = "user-1"
	list.Principals["user-1"] = list.Principals[wlPrincipal]
	value, _ = enrollmentACLValue(list)
	record.Metadata[aclKey] = value
	if err = policy.AuthorizeLocked(bare, DomainAccess{Operation: nativeStoreCommand, Fields: []string{"id"}}, record); err == nil {
		t.Fatal("the workload kind passed with a person's principal")
	}
	badSession := actor
	badSession.SessionID = "channel-message:1"
	if err = policy.AuthorizeLocked(badSession, DomainAccess{Operation: nativeStoreCommand, Fields: []string{"id"}}, record); err == nil {
		t.Fatal("the workload kind passed with another session form")
	}
}

// A narrowed policy holds at once, before anyone regrants: the list on the root is not the limit.
func TestWorkloadNarrowedPolicyHoldsOverAnEarlierGrant(t *testing.T) {
	w := newWLForest(t)
	wlEnroll(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "grant")
	actor := wlActor(w.f, wlAccount, wlRevision)
	access := wlStoreAccess(domainStoreReadOperation, wlContacts)
	if err := wlDecide(t, w.f, actor, access, "copy-contact"); err != nil {
		t.Fatal("the granted family was refused", err)
	}
	w.f.config.WorkloadPolicy = &DomainWorkloadPolicy{Issuer: wlIssuer, Families: map[string][]string{wlMessages: wlFamilyFields[wlMessages]}}
	aclFixtureRestart(t, w.f)
	if err := wlDecide(t, w.f, actor, access, "copy-contact"); err == nil {
		t.Fatal("a family the policy no longer names was read")
	}
	if err := wlDecide(t, w.f, actor, wlStoreAccess(domainStoreReadOperation, wlMessages), "copy-message"); err != nil {
		t.Fatal("the family the policy still names was refused", err)
	}
}

// A workload on the list changes nothing for anyone else on it.
func TestWorkloadGrantChangesNoOneElsesDecisions(t *testing.T) {
	w := newWLForest(t)
	before := w.otherDecisions(t)
	wlEnroll(t, w.f, EnrollmentWorkloadGrant, wlAccount, w.rootID, wlPrincipal, "grant")
	if !domainEqual(before, w.otherDecisions(t)) {
		t.Fatal("a workload grant changed a person's decision")
	}
	wlEnroll(t, w.f, EnrollmentWorkloadRevoke, wlAccount, w.rootID, wlPrincipal, "revoke")
	if !domainEqual(before, w.otherDecisions(t)) {
		t.Fatal("a workload revoke changed a person's decision")
	}
}

func (w wlForest) otherDecisions(t *testing.T) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, principal := range []string{aclFixtureOwner, "unit-member", "unit-stranger"} {
		actor := DomainVerified{PrincipalID: principal, Kind: "human", GrantRevision: wlRevision, ExpiresAt: domainNow() + 30, Scope: DomainScope{AccountID: wlAccount, Product: "manifest"}}
		w.otherActorDecisions(t, actor, result)
	}
	return result
}

func (w wlForest) otherActorDecisions(t *testing.T, actor DomainVerified, result map[string]string) {
	t.Helper()
	for _, id := range append([]string{w.rootID}, wlRecordIDs...) {
		for _, operation := range []string{domainStoreReadOperation, nativeStoreCommand, "read"} {
			for _, fields := range wlFieldSets() {
				access := DomainAccess{Operation: operation, Fields: fields, Reference: domainContains(fields, "reference")}
				result[actor.PrincipalID+"|"+id+"|"+operation+"|"+strings.Join(fields, ",")] = aclDecisionText(wlDecide(t, w.f, actor, access, id))
			}
		}
	}
}
