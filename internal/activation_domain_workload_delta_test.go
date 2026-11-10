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

func wbGuard(t *testing.T, purpose string) (*domainEngine, *domainEntry, stagedView) {
	t.Helper()
	config := wbConfig(t)
	config.ACLMetadataKey = aclKey
	g := wbGrant("acl-account", purpose)
	owned := DomainOwnedScope{Binding: stagedBinding{RootID: wlRoot, AccountID: g.AccountID}, Layout: config.ProvisioningProfile.Layout}
	entry := &domainEntry{actor: DomainVerified{Kind: domainWorkloadKind, Workload: &DomainWorkloadRun{domainWorkloadRunRevision, g, "labelled-run", "1"}}, owned: owned}
	return &domainEngine{config: config}, entry, stagedView{Records: map[string]stagedRecord{}}
}

func wbCreate(t *testing.T, entry *domainEntry, family string, data map[string]interface{}) stagedCreate {
	t.Helper()
	kind := workloadFamilyRules[family].kind
	fields := entry.owned.Layout.Fields
	create := wlCreate(family, data)
	create.Kind = entry.owned.Layout.Kinds[kind]
	create.Metadata[aclKey] = domainACLReferenceValue(wlRoot, kind)
	if kind == "associate" {
		create.Metadata[fields["accountId"]] = entry.owned.Binding.AccountID
		label := data["full_name"]
		if label == nil {
			label = ""
		}
		create.Metadata[fields["label"]] = label
		create.Metadata[fields["roleIds"]] = []string{}
	}
	return create
}

func wbObservation() map[string]interface{} {
	return map[string]interface{}{"contractRevision": "quickbooks-observation/1", "provider": "quickbooks", "connectionId": "labelled-connection", "entity": "Account", "externalId": "labelled-source", "environment": "sandbox", "realmId": "labelled-realm", "sourceRevision": strings.Repeat("a", 64), "source": map[string]interface{}{"Id": "labelled-source"}, "projectedFamily": nil, "projected": map[string]interface{}{}}
}

func TestBoundWorkloadSixExactCreateFamiliesAndCarrier(t *testing.T) {
	rows := map[string]map[string]interface{}{
		wlMessages: {"text": "LABELLED"}, wlConversations: {"is_archived": false, "title": "LABELLED"}, wlContacts: {"phone": "LABELLED"},
		"resource:png_import": {"attributes": wbObservation()}, "business:associate": {"type": "client", "full_name": "LABELLED"}, "business:job": {"title": "LABELLED", "quickbooks_id": "labelled-source"},
	}
	for family, data := range rows {
		d, entry, view := wbGuard(t, workloadFamilyRules[family].purpose)
		data["id"], data["account_id"] = "k", "acl-account"
		create := wbCreate(t, entry, family, data)
		if err := d.validateWorkloadDelta(entry, view, stagedDelta{Creates: []stagedCreate{create}}); err != nil {
			t.Fatalf("%s positive create: %v", family, err)
		}
		create.Metadata["arbitrary"] = "not allowed"
		if d.validateWorkloadDelta(entry, view, stagedDelta{Creates: []stagedCreate{create}}) == nil {
			t.Fatal("extra metadata accepted", family)
		}
	}
}

func TestBoundWorkloadSourceRulesAndLocalFieldsSurviveUpdates(t *testing.T) {
	cases := []struct {
		family, field string
		before, value interface{}
		allow         bool
	}{
		{wlMessages, "text", "old", "new", false},
		{wlConversations, "last_message", "old", "new", true},
		{wlConversations, "title", "local", "source", false},
		{wlConversations, "title", nil, "source", true},
		{wlConversations, "is_archived", false, true, false},
		{wlContacts, "phone", "local", "source", false},
		{wlContacts, "phone", nil, "source", true},
		{"business:associate", "full_name", "old", "new", true},
		{"business:associate", "user_id", nil, "forbidden", false},
		{"business:job", "title", "old", "new", true},
		{"business:job", "status", "local", "source", false},
	}
	for _, item := range cases {
		wbUpdateDecision(t, item.family, item.field, item.before, item.value, item.allow)
	}
}

func wbUpdateDecision(t *testing.T, family, field string, old, value interface{}, allow bool) {
	t.Helper()
	d, entry, view := wbGuard(t, workloadFamilyRules[family].purpose)
	before := map[string]interface{}{"id": "k", "account_id": "acl-account", field: old, "created_by": "LABELLED local provenance"}
	if family == "business:associate" {
		before["type"] = "client"
	}
	create := wbCreate(t, entry, family, before)
	record := stagedRecord{ID: "existing", Kind: create.Kind, Metadata: create.Metadata}
	view.Records[record.ID] = record
	after := map[string]interface{}{}
	for k, v := range before {
		after[k] = v
	}
	after[field] = value
	writes := []stagedWrite{{NodeID: record.ID, Key: "pngData", Value: after}}
	if family == "business:associate" {
		writes = append(writes, stagedWrite{NodeID: record.ID, Key: entry.owned.Layout.Fields["label"], Value: after["full_name"]})
	}
	err := d.validateWorkloadDelta(entry, view, stagedDelta{Writes: writes})
	if (err == nil) != allow {
		t.Fatalf("%s/%s complete update: %v, wanted %v", family, field, err, allow)
	}
}

func TestBoundWorkloadQueriesAndMutationsNeverUnionFamilies(t *testing.T) {
	purpose := wbPolicy().Purposes["messaging.sync"]
	positive := workloadStoreQuery{Family: wlMessages, Fields: []string{"id", "text"}, OrderBy: []string{"-created_at"}}
	if err := validateWorkloadQuery(positive, purpose); err != nil {
		t.Fatal(err)
	}
	positive.Fields = []string{"id", "phone"}
	if validateWorkloadQuery(positive, purpose) == nil {
		t.Fatal("contacts field widened messages query")
	}
	body := map[string]interface{}{"mutations": []interface{}{map[string]interface{}{"family": wlMessages, "data": map[string]interface{}{"phone": "LABELLED"}}, map[string]interface{}{"family": wlContacts, "data": map[string]interface{}{"phone": "LABELLED"}}}}
	if validateBoundWorkloadInput(DomainInput{Mode: "command", Body: wbJSON(t, body)}, purpose) == nil {
		t.Fatal("one family's complete permission authorized another's partial request")
	}
}

func TestBoundWorkloadAssociateCarrierAndObservationIdentityCannotMove(t *testing.T) {
	for _, damage := range []string{"kind", "roles", "label", "account", "reference"} {
		wbCarrierDenial(t, damage)
	}
	d, entry, view := wbGuard(t, "accounting.sync")
	data := wlRow()
	data["attributes"] = wbObservation()
	create := wbCreate(t, entry, "resource:png_import", data)
	view.Records["existing"] = stagedRecord{ID: "existing", Kind: create.Kind, Metadata: create.Metadata}
	changed := wlRow()
	attributes := wbObservation()
	attributes["realmId"] = "another-realm"
	changed["attributes"] = attributes
	if err := d.validateWorkloadDelta(entry, view, stagedDelta{Writes: []stagedWrite{wlPatch(changed)}}); err == nil {
		t.Fatal("observation source identity moved")
	}
}

func wbCarrierDenial(t *testing.T, damage string) {
	t.Helper()
	d, entry, view := wbGuard(t, "accounting.sync")
	data := wlRow()
	data["type"], data["full_name"] = "client", "LABELLED"
	create := wbCreate(t, entry, "business:associate", data)
	fields := entry.owned.Layout.Fields
	switch damage {
	case "kind":
		create.Kind = entry.owned.Layout.Kinds["png_record"]
	case "roles":
		create.Metadata[fields["roleIds"]] = []string{"ungranted-role"}
	case "label":
		create.Metadata[fields["label"]] = "not derived"
	case "account":
		create.Metadata[fields["accountId"]] = "another-account"
	case "reference":
		create.Metadata[aclKey] = domainACLReferenceValue(wlRoot, "png_record")
	}
	if d.validateWorkloadDelta(entry, view, stagedDelta{Creates: []stagedCreate{create}}) == nil {
		t.Fatal("carrier safety failed", damage)
	}
}
