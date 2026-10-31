// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"strings"
	"testing"
)

func aclReferenceRecord(id, kind string, value interface{}) DomainRecord {
	return DomainRecord{ID: id, Kind: aclKinds[kind], Metadata: map[string]interface{}{aclKey: value}}
}

func aclFullyGrantedActor(owned DomainOwnedScope) DomainVerified {
	return DomainVerified{PrincipalID: aclAdmin, Kind: "human", ExpiresAt: domainNow() + 30, Scope: aclScope(owned)}
}

func aclReadAccess() DomainAccess {
	return DomainAccess{Operation: aclStoreRead, Fields: []string{"id"}}
}

func TestDomainACLReferenceStoresNoListAndIsRefusedWithoutItsRoot(t *testing.T) {
	owned := aclOwned("acl-account", "acl-root")
	forest := newACLForest(t, aclReferences, owned)
	forest.create(t, "new-record", "png_record")
	stored, err := json.Marshal(forest.records["new-record"].Metadata[aclKey])
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) > 128 || strings.Contains(string(stored), aclAdmin) {
		t.Fatalf("record still carries the list: %s", stored)
	}
	policy := &domainOwnerPolicy{key: aclKey}
	if err = policy.AuthorizeLocked(aclFullyGrantedActor(owned), aclReadAccess(), forest.records["new-record"]); err == nil {
		t.Fatal("the policy read an unresolved reference as a list")
	}
	if err = forest.d.authorizeDomainRecord(aclFullyGrantedActor(owned), aclReadAccess(), forest.view(), forest.records["new-record"]); err != nil {
		t.Fatal("resolved reference denied", err)
	}
}

func TestDomainACLReferenceRefusals(t *testing.T) {
	owned := aclOwned("acl-account", "acl-root")
	other := newACLForest(t, aclReferences, aclOwned("acl-other-account", "acl-other-root"))
	cases := []struct {
		name   string
		record DomainRecord
		want   string
	}{
		{"another account's root", aclReferenceRecord("r", "png_record", domainACLReferenceValue(other.owned.Binding.RootID, "png_record")), "another root"},
		{"another kind's template", aclReferenceRecord("r", "png_record", domainACLReferenceValue("acl-root", "associate")), "another kind"},
		{"a kind outside the layout", aclReferenceRecord("r", "png_record", domainACLReferenceValue("acl-root", "absent-kind")), "another kind"},
		{"an empty root", aclReferenceRecord("r", "png_record", map[string]interface{}{"contractRevision": domainACLReferenceRevision, "rootId": "", "kind": "png_record"}), "invalid native ACL reference"},
		{"an extra member", aclReferenceRecord("r", "png_record", map[string]interface{}{"contractRevision": domainACLReferenceRevision, "rootId": "acl-root", "kind": "png_record", "principals": map[string]interface{}{}}), "invalid native ACL reference"},
		{"a non-string kind", aclReferenceRecord("r", "png_record", map[string]interface{}{"contractRevision": domainACLReferenceRevision, "rootId": "acl-root", "kind": 3}), "invalid native ACL reference"},
		{"a root holding a reference", aclReferenceRecord("acl-root", "root", domainACLReferenceValue("acl-root", "root")), "must hold its own ACL"},
	}
	for _, item := range cases {
		forest := newACLForest(t, aclReferences, owned)
		if item.record.ID == owned.Binding.RootID {
			forest.records[item.record.ID] = item.record
		}
		err := forest.d.authorizeDomainRecord(aclFullyGrantedActor(owned), aclReadAccess(), forest.view(), item.record)
		if err == nil || !strings.Contains(err.Error(), item.want) {
			t.Fatalf("%s: got %v, want %q", item.name, err, item.want)
		}
	}
}

func TestDomainACLReferenceRefusedWhenTemplateAbsentOrRootInvalid(t *testing.T) {
	owned := aclOwned("acl-account", "acl-root")
	record := aclReferenceRecord("r", "png_record", domainACLReferenceValue("acl-root", "png_record"))
	withoutTemplate := newACLForest(t, aclReferences, owned)
	delete(withoutTemplate.root().Metadata[aclKey].(map[string]interface{})["createACLs"].(map[string]interface{}), "png_record")
	if err := withoutTemplate.d.authorizeDomainRecord(aclFullyGrantedActor(owned), aclReadAccess(), withoutTemplate.view(), record); err == nil || !strings.Contains(err.Error(), "template absent") {
		t.Fatal("missing template did not fail closed", err)
	}
	invalidRoot := newACLForest(t, aclReferences, owned)
	invalidRoot.root().Metadata[aclKey].(map[string]interface{})["contractRevision"] = "lj.domain.acl/0"
	if err := invalidRoot.d.authorizeDomainRecord(aclFullyGrantedActor(owned), aclReadAccess(), invalidRoot.view(), record); err == nil {
		t.Fatal("invalid root list resolved a reference")
	}
	withoutRoot := newACLForest(t, aclReferences, owned)
	delete(withoutRoot.records, owned.Binding.RootID)
	if err := withoutRoot.d.authorizeDomainRecord(aclFullyGrantedActor(owned), aclReadAccess(), withoutRoot.view(), record); err == nil {
		t.Fatal("reference resolved with no root in the view")
	}
}

// Each account's records answer from its own root: a grant in one account changes nothing in the
// other, and a record is never in another scope's view at all.
func TestDomainACLReferenceAccountsAreIsolated(t *testing.T) {
	first := newACLForest(t, aclReferences, aclOwned("acl-account", "acl-root"))
	second := newACLForest(t, aclReferences, aclOwned("acl-other-account", "acl-other-root"))
	first.create(t, "first-record", "png_record")
	second.create(t, "second-record", "png_record")
	if outcome := first.readChange(EnrollmentReadGrant, aclMember, aclGrantRev1); outcome != "" {
		t.Fatal(outcome)
	}
	member := func(forest *aclForest) DomainVerified {
		return DomainVerified{PrincipalID: aclMember, Kind: "human", GrantRevision: aclGrantRev1, ExpiresAt: domainNow() + 30, Scope: aclScope(forest.owned)}
	}
	if err := first.d.authorizeDomainRecord(member(first), aclReadAccess(), first.view(), first.records["first-record"]); err != nil {
		t.Fatal("granted member denied in their own account", err)
	}
	if err := second.d.authorizeDomainRecord(member(second), aclReadAccess(), second.view(), second.records["second-record"]); err == nil {
		t.Fatal("a grant crossed accounts through a template")
	}
	intent := DomainIntent{Fields: []DomainFieldSet{{Resource: DomainResource{ResourceID: "first-record"}, Fields: []string{"id"}}}}
	crossing := member(second)
	crossing.Intent = intent
	if err := second.d.authorizeIntentLocked(crossing, second.view()); err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatal("another account's record reached evaluation", err)
	}
	planted := DomainRecord{ID: "planted", Kind: aclKinds["png_record"], Metadata: map[string]interface{}{aclKey: domainACLReferenceValue(first.owned.Binding.RootID, "png_record")}}
	if err := second.d.authorizeDomainRecord(member(second), aclReadAccess(), second.view(), planted); err == nil || !strings.Contains(err.Error(), "another root") {
		t.Fatal("a reference planted in another scope resolved", err)
	}
}

func TestDomainACLPolicyGetsAnIsolatedCopyOfTheTemplate(t *testing.T) {
	owned := aclOwned("acl-account", "acl-root")
	forest := newACLForest(t, aclReferences, owned)
	forest.create(t, "new-record", "png_record")
	before, _ := CanonicalDomainJSON(forest.root().Metadata[aclKey])
	copy, err := forest.d.domainResolvedPolicyRecord(aclFullyGrantedActor(owned), forest.view(), forest.records["new-record"])
	if err != nil {
		t.Fatal(err)
	}
	copy.Metadata[aclKey].(map[string]interface{})["principals"] = "poisoned"
	after, _ := CanonicalDomainJSON(forest.root().Metadata[aclKey])
	if string(before) != string(after) {
		t.Fatal("a policy copy aliased the root's template")
	}
	if _, isReference, _ := domainACLReferenceOf(forest.records["new-record"].Metadata[aclKey]); !isReference {
		t.Fatal("resolving wrote the list back onto the record")
	}
}

func TestDomainRecordACLProjectsFullListsAndReferences(t *testing.T) {
	owned := aclOwned("acl-account", "acl-root")
	forest := newACLForest(t, aclReferences, owned)
	forest.create(t, "new-record", "png_record")
	value, err := DomainRecordACL(owned, forest.view(), forest.records["new-record"])
	if err != nil {
		t.Fatal(err)
	}
	template, _ := domainACLTemplateValue(aclKey, forest.root(), "png_record")
	if !domainEqual(value, template) {
		t.Fatal("projection of a reference is not its template")
	}
	own, err := DomainRecordACL(owned, forest.view(), forest.root())
	if err != nil || !domainEqual(own, forest.root().Metadata[aclKey]) {
		t.Fatal("projection of a full list changed it", err)
	}
}

func TestDomainACLReaderDecodesEachTemplateOnceAndChecksEveryRecord(t *testing.T) {
	owned := aclOwned("acl-account", "acl-root")
	forest := newACLForest(t, aclReferences, owned)
	forest.create(t, "new-record", "png_record")
	reader := newDomainACLReader(aclKey, owned, forest.root())
	for attempt := 0; attempt < 3; attempt++ {
		acl, err := reader.acl(forest.records["new-record"])
		if err != nil || acl.Principals[aclAdmin] == nil {
			t.Fatal("reader did not resolve", err)
		}
	}
	if len(reader.templates) != 1 {
		t.Fatal("template decoded more than once")
	}
	wrongKind := aclReferenceRecord("r", "associate", domainACLReferenceValue("acl-root", "png_record"))
	if _, err := reader.acl(wrongKind); err == nil {
		t.Fatal("a memoized template answered a record of another kind")
	}
	own, err := reader.acl(forest.root())
	if err != nil || own.CreateACLs == nil {
		t.Fatal("reader changed a full list", err)
	}
}

// The cache spares decoding per record; it must never answer one kind with another's list.
func TestDomainACLReaderKeepsKindsApart(t *testing.T) {
	owned := aclOwned("acl-account", "acl-root")
	forest := newACLForest(t, aclReferences, owned)
	forest.create(t, "png-first", "png_record")
	forest.create(t, "associate-record", "associate")
	forest.create(t, "png-second", "png_record")
	reader := newDomainACLReader(aclKey, owned, forest.root())
	for _, id := range []string{"png-first", "associate-record", "png-second", "associate-record"} {
		record := forest.records[id]
		kind := "png_record"
		if record.Kind == aclKinds["associate"] {
			kind = "associate"
		}
		acl, err := reader.acl(record)
		if err != nil {
			t.Fatal(err)
		}
		want := owned.Layout.Profiles[aclStoreRead][kind]
		if got := acl.Principals[aclAdmin][aclStoreRead].Fields; !domainEqual(got, want) {
			t.Fatalf("%s was answered with %v, want its own kind's %v", id, got, want)
		}
	}
	if len(reader.templates) != 2 {
		t.Fatalf("expected one cached list per kind, got %d", len(reader.templates))
	}
}
