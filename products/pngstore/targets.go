// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"sort"
)

func TargetFields(input engine.DomainInput, owned engine.DomainOwnedScope, native engine.DomainRecord) []string {
	request, err := decode(input)
	if err != nil {
		return nil
	}
	return requestTargetFields(request, owned, native)
}

func requestTargetFields(request Request, owned engine.DomainOwnedScope, native engine.DomainRecord) []string {
	fields := map[string]bool{}
	for _, mutation := range request.Mutations {
		if targetMatches(mutation, native, owned) {
			mutationTargetFields(fields, mutation)
			addDefaultTargetFields(fields, request, mutation, owned.Layout.ApplicationCreateDefaults)
			addAssociateTargetFields(fields, mutation, owned)
		}
	}
	addCarrierTargetFields(fields, request, native, owned)
	result := []string{}
	for key := range fields {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
func addCarrierTargetFields(fields map[string]bool, request Request, native engine.DomainRecord, owned engine.DomainOwnedScope) {
	var result map[string]interface{}
	_ = engine.DecodeDomainJSON(request.Result, &result)
	if result["derive_carrier_events"] != true {
		return
	}
	if native.ID != "" && native.Metadata[field(owned, "pngFamily")] != "business:asset_event" {
		return
	}
	fields["family.business:asset_event"] = true
	for _, key := range owned.Layout.ApplicationCreateDefaults["business:asset_event"] {
		fields["data."+key] = true
	}
	for _, key := range []string{"id", "account_id", "entity_type", "entity_id", "event_type", "cause", "caused_by_event_id", "notes", "job_id", "employee_id", "location_id", "occurred_at"} {
		fields["data."+key] = true
	}
}
func targetMatches(mutation Mutation, native engine.DomainRecord, owned engine.DomainOwnedScope) bool {
	if native.ID == "" {
		return mutation.NativeID == "" && newMutationTargetKind(mutation, native, owned)
	}
	return native.Kind == owned.Layout.Kinds[mutationKind(mutation, owned)] && native.Metadata[field(owned, "pngFamily")] == mutation.Family && native.Metadata[field(owned, "pngKey")] == mutation.Key
}

func newMutationTargetKind(mutation Mutation, native engine.DomainRecord, owned engine.DomainOwnedScope) bool {
	if owned.Layout.AssociateCarrier == nil {
		return true
	}
	return native.Kind != "" && native.Kind == owned.Layout.Kinds[mutationKind(mutation, owned)]
}

func addAssociateTargetFields(fields map[string]bool, mutation Mutation, owned engine.DomainOwnedScope) {
	if mutationKind(mutation, owned) != "associate" {
		return
	}
	for _, field := range associateMutationFields(mutation) {
		fields[field] = true
	}
}
func mutationTargetFields(fields map[string]bool, mutation Mutation) {
	fields["family."+mutation.Family] = true
	fields["data.account_id"] = true
	fields["data.id"] = true
	for key := range mutation.Data {
		fields["data."+key] = true
	}
}
