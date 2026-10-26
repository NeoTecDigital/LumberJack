// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"sort"
)

func (Adapter) Resolve(input engine.DomainInput, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainIntent, error) {
	request, err := decode(input)
	if err != nil {
		return engine.DomainIntent{}, err
	}
	op := "png.store.read"
	if input.Mode == "command" {
		op = WriteOperation
	}
	route := owned.Layout.Routes[op]
	if route.Method != input.Method || route.Target != input.Target || request.Scope != (engine.DomainScope{AccountID: owned.Binding.AccountID, Product: owned.Binding.ProductID}) {
		return engine.DomainIntent{}, fmt.Errorf("native route/scope mismatch")
	}
	all, err := records(owned, view)
	if err != nil {
		return engine.DomainIntent{}, err
	}
	request, _, err = deriveCarriers(request, all)
	if err != nil {
		return engine.DomainIntent{}, err
	}
	selected, err := intentRecords(request, input.Mode, all, owned.Bounds.MaxNodes)
	if request.Query.Family == HistoryFamily {
		selected, err = historyRecords(request, view)
	}
	if err != nil {
		return engine.DomainIntent{}, err
	}
	refs, sets, err := intentFields(request, selected, op, owned, view)
	if err != nil {
		return engine.DomainIntent{}, err
	}
	intent := engine.DomainIntent{ContractRevision: Revision, Scope: request.Scope, Binding: engine.DomainBinding{Scope: request.Scope, RootID: owned.Binding.RootID, BindingRevision: owned.Binding.BindingRevision}, Mode: input.Mode, Method: input.Method, Target: input.Target, RequestFingerprint: hashBody(input.Body), Resources: refs, Fields: sets}
	if input.Mode == "command" {
		intent.Operation = &request.Operation
	}
	return intent, nil
}
func hashBody(raw []byte) string {
	var value interface{}
	_ = engine.DecodeDomainJSON(raw, &value)
	return hash(value)
}
func intentRecords(request Request, mode string, all []Record, maximum int) ([]Record, error) {
	if mode == "read" {
		return selectRecords(request.Query, all, maximum)
	}
	selected := map[string]Record{}
	for _, mutation := range request.Mutations {
		addMutationTarget(selected, all, mutation)
	}
	for _, reference := range request.References {
		record, present := find(all, reference.Family, reference.Key)
		if !present {
			return nil, fmt.Errorf("native reference absent")
		}
		selected[record.NativeID] = record
	}
	for _, unique := range request.Unique {
		addUniqueFamily(selected, all, unique.Family, request.Mutations)
	}
	result := []Record{}
	for _, record := range selected {
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].NativeID < result[j].NativeID })
	return result, nil
}
func addMutationTarget(selected map[string]Record, all []Record, mutation Mutation) {
	if mutation.NativeID == "" {
		return
	}
	if record, present := find(all, mutation.Family, mutation.Key); present {
		selected[record.NativeID] = record
	}
}
func addUniqueFamily(selected map[string]Record, all []Record, family string, mutations []Mutation) {
	for _, record := range all {
		if record.Family == family && !newlyCreated(record, mutations) {
			selected[record.NativeID] = record
		}
	}
}
func newlyCreated(record Record, mutations []Mutation) bool {
	for _, mutation := range mutations {
		if mutation.NativeID == "" && mutation.Family == record.Family && mutation.Key == record.Key {
			return true
		}
	}
	return false
}
func intentFields(request Request, selected []Record, operation string, owned engine.DomainOwnedScope, view engine.DomainView) ([]engine.DomainResource, []engine.DomainFieldSet, error) {
	refs := []engine.DomainResource{{AccountID: owned.Binding.AccountID, Kind: "root", ResourceID: owned.Binding.RootID}}
	for _, record := range selected {
		kind, err := storeSemanticKind(record, owned, view)
		if err != nil {
			return nil, nil, err
		}
		refs = append(refs, engine.DomainResource{AccountID: owned.Binding.AccountID, Kind: kind, ResourceID: record.NativeID})
	}
	sets := []engine.DomainFieldSet{}
	for _, resource := range refs {
		ceiling := owned.Layout.Profiles[operation][resource.Kind]
		fields := storeBaseFields(ceiling, owned)
		if len(fields) == 0 {
			return nil, nil, fmt.Errorf("native store field profile absent")
		}
		fields = append(fields, requiredDataFields(request, selected, resource.ResourceID, operation, owned.Binding.RootID, owned.Layout.ApplicationCreateDefaults)...)
		fields = append(fields, requiredFamilyFields(request, selected, resource.ResourceID, owned.Binding.RootID)...)
		fields = append(fields, associateIntentFields(request, resource.ResourceID, owned.Binding.RootID, owned)...)
		if referenced(request, resource.ResourceID) {
			fields = append(fields, "reference")
		}
		fields = uniqueFields(fields)
		if err := checkStoreCeiling(fields, ceiling); err != nil {
			return nil, nil, err
		}
		sets = append(sets, engine.DomainFieldSet{Resource: resource, Fields: fields})
	}
	return refs, sets, nil
}
func uniqueFields(fields []string) []string {
	seen := map[string]bool{}
	for _, field := range fields {
		seen[field] = true
	}
	result := []string{}
	for field := range seen {
		result = append(result, field)
	}
	sort.Strings(result)
	return result
}
func referenced(request Request, id string) bool {
	for _, reference := range request.References {
		if reference.NativeID == id {
			return true
		}
	}
	return false
}
func (Adapter) ProjectInput(requestID string, input engine.DomainInput, intent engine.DomainIntent, owned engine.DomainOwnedScope, view engine.DomainView) ([]byte, error) {
	request, err := decode(input)
	if err != nil {
		return nil, err
	}
	if request.Query.Family == HistoryFamily {
		return historyBody(requestID, request, intent, view)
	}
	all, err := records(owned, view)
	if err != nil {
		return nil, err
	}
	selected, err := selectRecords(request.Query, all, owned.Bounds.MaxNodes)
	if err != nil {
		return nil, err
	}
	selected = maskRecords(selected, request.Query.Fields)
	return engine.CanonicalDomainJSON(map[string]interface{}{"contractRevision": Revision, "requestId": requestID, "scope": intent.Scope, "revision": view.Revision, "records": selected})
}
