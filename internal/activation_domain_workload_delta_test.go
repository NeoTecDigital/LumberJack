// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"strings"
	"testing"
)

const wlRoot = "acl-root"

func wlGuardEntry(kind string) (*domainEngine, *domainEntry, stagedView) {
	config := DomainConfig{ACLMetadataKey: aclKey, WorkloadPolicy: wlPolicy()}
	layout := DomainLayout{Kinds: map[string]string{"root": "native.root", "png_record": "native.png_record", "associate": "native.associate"}, Fields: map[string]string{"pngKey": "pngKey", "pngFamily": "pngFamily", "pngData": "pngData", "pngVersion": "pngVersion"}}
	owned := DomainOwnedScope{Binding: stagedBinding{RootID: wlRoot, AccountID: "acl-account"}, Layout: layout}
	existing := DomainRecord{ID: "existing", Kind: "native.png_record", Metadata: map[string]interface{}{"pngKey": "existing", "pngFamily": wlMessages, "pngVersion": "v", "pngData": map[string]interface{}{"id": "existing", "account_id": "acl-account", "text": "old", "salary": "kept"}}}
	job := DomainRecord{ID: "job", Kind: "native.png_record", Metadata: map[string]interface{}{"pngKey": "job", "pngFamily": wlOtherFamily, "pngVersion": "v", "pngData": map[string]interface{}{"id": "job"}}}
	associate := DomainRecord{ID: "person", Kind: "native.associate", Metadata: map[string]interface{}{"pngFamily": wlMessages}}
	view := stagedView{Records: map[string]stagedRecord{wlRoot: {ID: wlRoot, Kind: "native.root"}, "existing": existing, "job": job, "person": associate}}
	return &domainEngine{config: config}, &domainEntry{actor: DomainVerified{Kind: kind}, owned: owned}, view
}

func wlCreate(family string, data map[string]interface{}) stagedCreate {
	return stagedCreate{ID: "new", ParentID: wlRoot, Kind: "native.png_record", Name: "k", Metadata: map[string]interface{}{"pngKey": "k", "pngFamily": family, "pngVersion": "v", "pngData": data, aclKey: domainACLReferenceValue(wlRoot, "png_record")}}
}

func wlRow(extra ...string) map[string]interface{} {
	row := map[string]interface{}{"id": "k", "account_id": "acl-account"}
	for _, key := range extra {
		row[key] = "labelled"
	}
	return row
}

func wlPatch(data map[string]interface{}) stagedWrite {
	return stagedWrite{NodeID: "existing", Key: "pngData", Value: data}
}

func wlExistingData(changes map[string]interface{}, removed ...string) map[string]interface{} {
	data := map[string]interface{}{"id": "existing", "account_id": "acl-account", "text": "old", "salary": "kept"}
	for key, value := range changes {
		data[key] = value
	}
	for _, key := range removed {
		delete(data, key)
	}
	return data
}

type wlDeltaCase struct {
	name  string
	delta stagedDelta
	want  string
}

func wlEdited(edit func(*stagedCreate)) stagedDelta {
	create := wlCreate(wlMessages, wlRow())
	edit(&create)
	return stagedDelta{Creates: []stagedCreate{create}}
}

func wlCreateCases() []wlDeltaCase {
	return []wlDeltaCase{
		{"a message", stagedDelta{Creates: []stagedCreate{wlCreate(wlMessages, wlRow("text"))}}, ""},
		{"a conversation", stagedDelta{Creates: []stagedCreate{wlCreate(wlConversations, wlRow("title"))}}, ""},
		{"a contact", stagedDelta{Creates: []stagedCreate{wlCreate(wlContacts, wlRow("phone"))}}, ""},
		{"another family", stagedDelta{Creates: []stagedCreate{wlCreate(wlOtherFamily, wlRow())}}, "family denied"},
		{"another family's column", stagedDelta{Creates: []stagedCreate{wlCreate(wlMessages, wlRow("phone"))}}, "field denied"},
		{"a column in no list", stagedDelta{Creates: []stagedCreate{wlCreate(wlMessages, wlRow("salary"))}}, "field denied"},
		{"a child of another kind", wlEdited(func(c *stagedCreate) { c.Kind = "native.associate" }), "only a store record"},
		{"a child of another parent", wlEdited(func(c *stagedCreate) { c.ParentID = "existing" }), "only a store record"},
		{"its own access list", wlEdited(func(c *stagedCreate) {
			c.Metadata[aclKey] = map[string]interface{}{"contractRevision": domainACLRevision, "principals": map[string]interface{}{}}
		}), "must follow"},
		{"another root's list", wlEdited(func(c *stagedCreate) { c.Metadata[aclKey] = domainACLReferenceValue("other-root", "png_record") }), "must follow"},
		{"another kind's list", wlEdited(func(c *stagedCreate) { c.Metadata[aclKey] = domainACLReferenceValue(wlRoot, "associate") }), "must follow"},
		{"an extra metadata key", wlEdited(func(c *stagedCreate) { c.Metadata["label"] = "labelled" }), "only a store record"},
		{"a foreign account", stagedDelta{Creates: []stagedCreate{wlCreate(wlMessages, map[string]interface{}{"id": "k", "account_id": "other"})}}, "identity"},
		{"a mismatched id", stagedDelta{Creates: []stagedCreate{wlCreate(wlMessages, map[string]interface{}{"id": "other", "account_id": "acl-account"})}}, "identity"},
	}
}

func wlWriteCases() []wlDeltaCase {
	return []wlDeltaCase{
		{"a field it holds", stagedDelta{Writes: []stagedWrite{wlPatch(wlExistingData(map[string]interface{}{"text": "new"}))}}, ""},
		{"a kept field outside its list", stagedDelta{Writes: []stagedWrite{wlPatch(wlExistingData(nil))}}, ""},
		{"a changed field outside its list", stagedDelta{Writes: []stagedWrite{wlPatch(wlExistingData(map[string]interface{}{"salary": "changed"}))}}, "field denied"},
		{"a removed field outside its list", stagedDelta{Writes: []stagedWrite{wlPatch(wlExistingData(nil, "salary"))}}, "field denied"},
		{"another family's record", stagedDelta{Writes: []stagedWrite{{NodeID: "job", Key: "pngData", Value: map[string]interface{}{"id": "job"}}}}, "family denied"},
		{"a record of another kind", stagedDelta{Writes: []stagedWrite{{NodeID: "person", Key: "pngData", Value: wlRow()}}}, "only a store record"},
		{"the root", stagedDelta{Writes: []stagedWrite{{NodeID: wlRoot, Key: "pngData", Value: wlRow()}}}, "only a store record"},
		{"an access list", stagedDelta{Writes: []stagedWrite{{NodeID: "existing", Key: aclKey, Value: map[string]interface{}{}}}}, "metadata change"},
		{"another metadata key", stagedDelta{Writes: []stagedWrite{{NodeID: "existing", Key: "label", Value: "x"}}}, "metadata change"},
		{"moving the family", stagedDelta{Writes: []stagedWrite{{NodeID: "existing", Key: "pngFamily", Value: wlContacts}}}, "cannot move"},
		{"moving the key", stagedDelta{Writes: []stagedWrite{{NodeID: "existing", Key: "pngKey", Value: "other"}}}, "cannot move"},
		{"an enrollment record", stagedDelta{EnrollmentRecord: []byte("{}")}, "outside the native store"},
		{"a mapping record", stagedDelta{MappingRecord: []byte("{}")}, "outside the native store"},
		{"a follower statement", stagedDelta{Followers: map[string]int{"png_record": 1}}, "outside the native store"},
	}
}

func TestWorkloadDeltaHoldsToItsFamiliesAndFields(t *testing.T) {
	for _, item := range append(wlCreateCases(), wlWriteCases()...) {
		d, entry, view := wlGuardEntry(domainWorkloadKind)
		err := d.validateWorkloadDelta(entry, view, item.delta)
		if item.want == "" && err != nil || item.want != "" && (err == nil || !strings.Contains(err.Error(), item.want)) {
			t.Fatalf("%s: got %v, want %q", item.name, err, item.want)
		}
	}
}

func TestWorkloadDeltaPolicyNarrowingHolds(t *testing.T) {
	d, entry, view := wlGuardEntry(domainWorkloadKind)
	d.config.WorkloadPolicy = &DomainWorkloadPolicy{Issuer: wlIssuer, Families: map[string][]string{wlMessages: wlFamilyFields[wlMessages]}}
	err := d.validateWorkloadDelta(entry, view, stagedDelta{Creates: []stagedCreate{wlCreate(wlContacts, wlRow())}})
	if err == nil || !strings.Contains(err.Error(), "not granted") {
		t.Fatal("a family the policy left out was written", err)
	}
	d.config.WorkloadPolicy = nil
	if err = d.validateWorkloadDelta(entry, view, stagedDelta{}); err == nil {
		t.Fatal("a workload change passed with no policy")
	}
}

func TestPersonDeltaIsNotHeldToAWorkloadList(t *testing.T) {
	d, entry, view := wlGuardEntry("human")
	d.config.WorkloadPolicy = nil
	delta := stagedDelta{Creates: []stagedCreate{wlCreate(wlOtherFamily, wlRow("salary"))}, EnrollmentRecord: []byte("{}")}
	if err := d.validateWorkloadDelta(entry, view, delta); err != nil {
		t.Fatal(err)
	}
}
