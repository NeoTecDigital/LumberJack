// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"testing"
)

// These adapter tests inspect candidates only; embedded tests verify real durability.
func TestAssociateCarrierCreatesSingleCanonicalNodeAndSeparatesIDs(t *testing.T) {
	owned, view := associateTestView()
	delta := associateTestBuild(t, owned, view, associateTestMutation())
	if len(delta.Creates) != 1 || len(delta.Writes) != 0 {
		t.Fatal("carrier was not one actual native creation")
	}
	node := delta.Creates[0]
	if node.Kind != owned.Layout.Kinds["associate"] || node.ID == "canonical-associate" || node.Metadata[field(owned, "pngKey")] != "canonical-associate" {
		t.Fatal("canonical business identity impersonated native identity")
	}
	if node.Metadata[field(owned, "accountId")] != "account" || node.Metadata[field(owned, "label")] != "Reviewed name" {
		t.Fatal("derived graph account/label missing")
	}
	associateTestApply(view, delta)
	all, err := records(owned, view)
	record, found := find(all, AssociateFamily, "canonical-associate")
	if err != nil || !found || record.NativeID != node.ID {
		t.Fatal("canonical/native mapping was not retained in the same node", err)
	}
}

func TestAssociateCarrierPatchPreservesBusinessRolesAndHiddenFields(t *testing.T) {
	owned, view := associateTestView()
	associateTestApply(view, associateTestBuild(t, owned, view, associateTestMutation()))
	all, _ := records(owned, view)
	current, _ := find(all, AssociateFamily, "canonical-associate")
	view.Records["role-a"] = engine.DomainRecord{ID: "role-a", Kind: owned.Layout.Kinds["role"], Metadata: map[string]interface{}{field(owned, "accountId"): "account"}}
	view.Records[current.NativeID].Metadata[field(owned, "roleIds")] = []string{"role-a"}
	patch := Mutation{Family: current.Family, Key: current.Key, NativeID: current.NativeID, ExpectedVersion: current.Version, Patch: true, Data: map[string]interface{}{"full_name": "Changed name"}}
	delta := associateTestBuild(t, owned, view, patch)
	for _, write := range delta.Writes {
		if write.Key == field(owned, "roleIds") {
			t.Fatal("business patch tried to overwrite stacked business Roles")
		}
	}
	associateTestApply(view, delta)
	all, err := records(owned, view)
	changed, _ := find(all, AssociateFamily, current.Key)
	if err != nil || changed.Data["phone"] != "+15550002000" || view.Records[current.NativeID].Metadata[field(owned, "label")] != "Changed name" {
		t.Fatal("patch lost hidden business field or derived label", err)
	}
}

func TestAssociateCarrierRefusesGenericLegacyRowsEvenForUnrelatedScans(t *testing.T) {
	owned, view := associateTestView()
	legacy := view.Records["native-1"]
	legacy.Metadata[field(owned, "pngFamily")] = AssociateFamily
	view.Records["native-1"] = legacy
	request := Request{ContractRevision: Revision, Scope: engine.DomainScope{AccountID: "account", Product: "manifest"}, Action: "migration.apply.associate", Query: Query{Family: "migration.alias", Limit: 1}}
	if _, err := (Adapter{}).Resolve(associateTestInput(t, request, "read"), owned, view); err == nil {
		t.Fatal("alias/duplicate scan could certify an unmapped generic Associate")
	}
	if len(view.Records) != 2 {
		t.Fatal("legacy scan created or promoted a node")
	}
}

func TestAssociateCarrierRequiresExplicitPolicyAndSeparateProfiles(t *testing.T) {
	cases := []func(*engine.DomainOwnedScope){
		func(o *engine.DomainOwnedScope) { o.Layout.AssociateCarrier.NullLabel = nil },
		func(o *engine.DomainOwnedScope) { o.Layout.AssociateCarrier.InitialRoleIDs = nil },
		func(o *engine.DomainOwnedScope) { o.Layout.AssociateCarrier.InitialRoleIDs = []string{"role-a"} },
		func(o *engine.DomainOwnedScope) { o.Layout.AssociateCarrier.LabelField = "email" },
		func(o *engine.DomainOwnedScope) { o.Layout.AssociateCarrier.NativeKind = "png_record" },
		func(o *engine.DomainOwnedScope) { delete(o.Layout.Profiles["png.store.read"], "associate") },
		func(o *engine.DomainOwnedScope) { delete(o.Layout.Profiles[WriteOperation], "associate") },
		func(o *engine.DomainOwnedScope) {
			o.Layout.Profiles[WriteOperation]["associate"] = []string{"id", "pngKey", "pngFamily", "pngData", "pngVersion"}
		},
	}
	for index, change := range cases {
		owned, _ := associateTestView()
		change(&owned)
		if validateAssociateCarrier(owned, "fixture.acl") == nil {
			t.Fatalf("incomplete carrier policy/profile %d accepted", index)
		}
	}
}

func TestAssociateCarrierRejectsControlledNativeKindsRolesAndInvalidLabels(t *testing.T) {
	for _, name := range []string{"nativeKind", "native_kind", "roleIds", "role_ids", "fixture.roleIds", "full_name"} {
		owned, view := associateTestView()
		mutation := associateTestMutation()
		mutation.Data[name] = []string{"role-a"}
		request := associateTestRequest(mutation)
		if delta, err := (Adapter{}).Build(associateTestInput(t, request, "command"), owned, view); err == nil || len(delta.Creates) != 0 || len(delta.Writes) != 0 {
			t.Fatalf("request-controlled %s was accepted or partially applied", name)
		}
	}
}

func TestAssociateCarrierDoesNotFallbackToGenericCreateTemplate(t *testing.T) {
	owned, view := associateTestView()
	view.CreateACL = func(kind string) (interface{}, error) {
		if kind == "png_record" {
			return map[string]interface{}{"fixture": true}, nil
		}
		return nil, fmt.Errorf("Associate template is deliberately absent")
	}
	request := associateTestRequest(associateTestMutation())
	delta, err := (Adapter{}).Build(associateTestInput(t, request, "command"), owned, view)
	if err == nil || len(delta.Creates) != 0 || len(view.Records) != 2 {
		t.Fatal("generic create template authorized Associate creation")
	}
}

func TestAssociateCarrierLaterFailureReturnsNoPartialCandidate(t *testing.T) {
	owned, view := associateTestView()
	view.CreateACL = func(kind string) (interface{}, error) {
		if kind == "associate" {
			return map[string]interface{}{"fixture": true}, nil
		}
		return nil, fmt.Errorf("later evidence template absent")
	}
	request := associateTestRequest(associateTestMutation(), Mutation{Family: "migration.alias", Key: "alias", Data: map[string]interface{}{"id": "alias", "account_id": "account"}})
	delta, err := (Adapter{}).Build(associateTestInput(t, request, "command"), owned, view)
	if err == nil || len(delta.Creates) != 0 || len(delta.Writes) != 0 || len(view.Records) != 2 {
		t.Fatal("failed mixed transaction leaked a partial candidate")
	}
}

func TestAssociateCarrierReadIntentUsesActualKindWithoutGraphFieldExposure(t *testing.T) {
	owned, view := associateTestView()
	associateTestApply(view, associateTestBuild(t, owned, view, associateTestMutation()))
	request := Request{ContractRevision: Revision, Scope: engine.DomainScope{AccountID: "account", Product: "manifest"}, Action: "fixture.read", Query: Query{Family: AssociateFamily, Limit: 1, Fields: []string{"id", "account_id"}}}
	intent, err := (Adapter{}).Resolve(associateTestInput(t, request, "read"), owned, view)
	if err != nil || len(intent.Resources) != 2 || intent.Resources[1].Kind != "associate" {
		t.Fatal("canonical query did not bind actual Associate resource kind", err)
	}
	for _, set := range intent.Fields {
		if hasAssociateTestField(set.Fields, "roleIds") || hasAssociateTestField(set.Fields, "label") || hasAssociateTestField(set.Fields, "data.full_name") {
			t.Fatal("canonical read implicitly requested graph/hidden fields")
		}
	}
}

func TestAssociateCarrierMixedNewTargetsHaveKindSpecificFields(t *testing.T) {
	owned, _ := associateTestView()
	request := associateTestRequest(associateTestMutation(), Mutation{Family: "migration.alias", Key: "alias", Data: map[string]interface{}{"id": "alias", "account_id": "account"}})
	input := associateTestInput(t, request, "command")
	associate := TargetFields(input, owned, engine.DomainRecord{Kind: owned.Layout.Kinds["associate"]})
	generic := TargetFields(input, owned, engine.DomainRecord{Kind: owned.Layout.Kinds["png_record"]})
	if !hasAssociateTestField(associate, "roleIds") || hasAssociateTestField(generic, "roleIds") || hasAssociateTestField(generic, "family.business:associate") {
		t.Fatal("generic store grant/profile was reused as Associate target authority")
	}
	if !hasAssociateTestField(generic, "family.migration.alias") || hasAssociateTestField(associate, "family.migration.alias") {
		t.Fatal("mixed target family authority was not separated by actual kind")
	}
}

func TestAssociateCarrierExplicitNullLabelAndDisabledCompatibility(t *testing.T) {
	owned, view := associateTestView()
	mutation := associateTestMutation()
	mutation.Data["full_name"] = nil
	delta := associateTestBuild(t, owned, view, mutation)
	if delta.Creates[0].Metadata[field(owned, "label")] != "" {
		t.Fatal("reviewed explicit null label was not retained")
	}
	owned.Layout.AssociateCarrier = nil
	delta = associateTestBuild(t, owned, view, mutation)
	if delta.Creates[0].Kind != owned.Layout.Kinds["png_record"] {
		t.Fatal("absent opt-in changed the existing generic store")
	}
}

func associateTestView() (engine.DomainOwnedScope, engine.DomainView) {
	owned, view := testView()
	owned.Binding.ProductID, owned.Bounds.MaxNodes = "manifest", 20
	owned.Layout.Kinds["root"], owned.Layout.Kinds["associate"], owned.Layout.Kinds["role"] = "fixture.root", "fixture.associate", "fixture.role"
	for _, name := range []string{"accountId", "label", "roleIds"} {
		owned.Layout.Fields[name] = "fixture." + name
	}
	null := ""
	owned.Layout.AssociateCarrier = &engine.DomainAssociateCarrierPolicy{ContractRevision: AssociateCarrierRevision, Family: AssociateFamily, NativeKind: "associate", LabelField: "full_name", NullLabel: &null, InitialRoleIDs: []string{}}
	fields := []string{"id", "pngKey", "pngFamily", "pngData", "pngVersion", "accountId", "label", "roleIds", "data.id", "data.account_id", "data.full_name", "data.phone", "family.business:associate", "family.migration.alias"}
	owned.Layout.Routes, owned.Layout.Profiles = map[string]engine.DomainRoute{}, map[string]map[string][]string{}
	for _, operation := range []string{"png.store.read", WriteOperation} {
		owned.Layout.Routes[operation] = engine.DomainRoute{Method: "POST", Target: "/fixture/store"}
		owned.Layout.Profiles[operation] = map[string][]string{"root": fields, "png_record": fields, "associate": fields}
	}
	view.Records["root"] = engine.DomainRecord{ID: "root", Kind: "fixture.root", Metadata: map[string]interface{}{}}
	next := 0
	view.AllocateID = func() (string, error) { next++; return fmt.Sprintf("allocated-native-%d", next), nil }
	view.CreateACL = func(kind string) (interface{}, error) { return map[string]interface{}{"fixture-kind": kind}, nil }
	view.ACLMetadataKey = "fixture.acl"
	return owned, view
}

func associateTestMutation() Mutation {
	return Mutation{Family: AssociateFamily, Key: "canonical-associate", Data: map[string]interface{}{"id": "canonical-associate", "account_id": "account", "full_name": "Reviewed name", "phone": "+15550002000"}}
}

func associateTestRequest(mutations ...Mutation) Request {
	return Request{ContractRevision: Revision, Scope: engine.DomainScope{AccountID: "account", Product: "manifest"}, Action: "migration.apply.associate", Operation: WriteOperation, CommandID: "fixture-command", ExpectedRevision: "fixture-revision", Mutations: mutations}
}

func associateTestInput(t *testing.T, request Request, mode string) engine.DomainInput {
	t.Helper()
	raw, err := engine.CanonicalDomainJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	return engine.DomainInput{Mode: mode, Method: "POST", Target: "/fixture/store", Body: raw}
}

func associateTestBuild(t *testing.T, owned engine.DomainOwnedScope, view engine.DomainView, mutations ...Mutation) engine.DomainDelta {
	t.Helper()
	delta, err := (Adapter{}).Build(associateTestInput(t, associateTestRequest(mutations...), "command"), owned, view)
	if err != nil {
		t.Fatal(err)
	}
	return delta
}

func associateTestApply(view engine.DomainView, delta engine.DomainDelta) {
	for _, node := range delta.Creates {
		view.Records[node.ID] = engine.DomainRecord{ID: node.ID, Kind: node.Kind, Metadata: node.Metadata}
	}
	for _, write := range delta.Writes {
		view.Records[write.NodeID].Metadata[write.Key] = write.Value
	}
}

func hasAssociateTestField(fields []string, field string) bool {
	for _, candidate := range fields {
		if candidate == field {
			return true
		}
	}
	return false
}
