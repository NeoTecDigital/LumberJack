// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"encoding/json"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"testing"
)

func TestExplicitAliasVersionAndMaskedProjection(t *testing.T) {
	owned, view := testView()
	all, err := records(owned, view)
	if err != nil {
		t.Fatal(err)
	}
	wrong := Mutation{Family: "business:job", Key: "job-1", NativeID: "job-1", ExpectedVersion: "v1", Data: map[string]interface{}{"account_id": "account"}}
	if checkMutation(wrong, all) == nil {
		t.Fatal("canonical business ID impersonated native alias")
	}
	wrong.NativeID = "native-1"
	wrong.ExpectedVersion = "stale"
	if checkMutation(wrong, all) == nil {
		t.Fatal("stale native version accepted")
	}
	wrong.ExpectedVersion = "v1"
	if err = checkMutation(wrong, all); err != nil {
		t.Fatal(err)
	}
	masked := maskRecords(all, []string{"id", "account_id", "name"})
	if _, exposed := masked[0].Data["private"]; exposed {
		t.Fatal("private JSON field escaped projection")
	}
}
func TestAtomicUniquenessAndForeignScope(t *testing.T) {
	owned, view := testView()
	all, _ := records(owned, view)
	request := Request{Mutations: []Mutation{{Family: "business:job", Key: "new", Data: map[string]interface{}{"account_id": "foreign"}}}}
	if validateTransaction(request, all, owned) == nil {
		t.Fatal("foreign native account accepted")
	}
	request.Mutations[0].Data["account_id"] = "account"
	request.Unique = []Unique{{Family: "business:job", Fields: map[string]interface{}{"name": "retained"}}}
	if validateTransaction(request, all, owned) == nil {
		t.Fatal("native uniqueness conflict accepted")
	}
}
func TestCarrierDerivationPreservesExactReferences(t *testing.T) {
	result, _ := json.Marshal(map[string]interface{}{"derive_carrier_events": true})
	presence := Mutation{Family: "business:presence_event", Key: "presence", Data: map[string]interface{}{"account_id": "account", "event_type": "arrived", "employee_id": "employee", "job_id": "job", "occurred_at": "exact-stamp"}}
	asset := Record{Family: "business:asset", Key: "asset", NativeID: "native-asset", Version: "retained-v", Data: map[string]interface{}{"account_id": "account", "type": "tool", "assigned_to_employee_id": "employee"}}
	request, count, err := deriveCarriers(Request{Mutations: []Mutation{presence}, Result: result}, []Record{asset})
	if err != nil || count != 1 || len(request.Mutations) != 2 {
		t.Fatalf("carrier derivation: %v/%d", err, count)
	}
	derived := request.Mutations[1]
	if derived.Data["event_type"] != "moved_to_job" || derived.Data["cause"] != "carrier_moved" || derived.Data["occurred_at"] != "exact-stamp" {
		t.Fatal("carrier source semantics changed")
	}
	if request.References[0].NativeID != "native-asset" || request.References[0].Version != "retained-v" {
		t.Fatal("carrier native reference not fenced")
	}
}
func testView() (engine.DomainOwnedScope, engine.DomainView) {
	owned := engine.DomainOwnedScope{Binding: engine.DomainNativeBinding{AccountID: "account", RootID: "root"}, Bounds: engine.DomainBounds{MaxChanges: 10, MaxIdentifierBytes: 200}, Layout: engine.DomainLayout{Kinds: map[string]string{"png_record": "native.kind"}, Fields: map[string]string{"pngKey": "key", "pngFamily": "family", "pngData": "data", "pngVersion": "version"}}}
	metadata := map[string]interface{}{"key": "job-1", "family": "business:job", "version": "v1", "data": map[string]interface{}{"id": "job-1", "account_id": "account", "name": "retained", "private": "must-not-disclose"}}
	view := engine.DomainView{Records: map[string]engine.DomainRecord{"native-1": {ID: "native-1", Kind: "native.kind", Metadata: metadata}}}
	return owned, view
}

func TestAtomicCandidateUniquenessAndInclusiveTeamInterval(t *testing.T) {
	owned, _ := testView()
	data := func(id string) map[string]interface{} {
		return map[string]interface{}{"id": id, "account_id": "account", "name": "same"}
	}
	request := Request{Mutations: []Mutation{{Family: "business:job", Key: "a", Data: data("a")}, {Family: "business:job", Key: "b", Data: data("b")}}, Unique: []Unique{{Family: "business:job", Fields: map[string]interface{}{"name": "same"}}}}
	if validateTransaction(request, nil, owned) == nil {
		t.Fatal("two candidate records escaped atomic uniqueness")
	}
	assignment := Record{Data: map[string]interface{}{"assigned_date": "2026-10-01", "end_date": "2026-10-14"}}
	if !activeOn(assignment, "2026-10-14") || activeOn(assignment, "2026-10-15") {
		t.Fatal("source inclusive assignment interval changed")
	}
}
func TestOwnerDefaultsPreserveProvidedAndImportsRejectNull(t *testing.T) {
	owned, _ := testView()
	owned.Layout.ApplicationCreateDefaults = map[string][]string{"business:job": {"created_at"}}
	request := Request{Action: "application.create", Mutations: []Mutation{{Family: "business:job", Key: "job", Data: map[string]interface{}{"account_id": "account"}}}}
	changed, err := applicationDefaults(request, owned)
	if err != nil || changed.Mutations[0].Data["created_at"] == nil {
		t.Fatal("explicit owner application default unavailable", err)
	}
	request.Mutations[0].Data["created_at"] = "provided-exact"
	changed, err = applicationDefaults(request, owned)
	if err != nil || changed.Mutations[0].Data["created_at"] != "provided-exact" {
		t.Fatal("provided timestamp changed")
	}
	request.Mutations[0].Data["created_at"] = nil
	if _, err = applicationDefaults(request, owned); err == nil {
		t.Fatal("explicit application null was silently coalesced")
	}
	request.Action = "migration.apply"
	changed, err = applicationDefaults(request, owned)
	if err != nil || changed.Mutations[0].Data["created_at"] != nil {
		t.Fatal("imported explicit timestamp/null mutated by application defaults")
	}
}
