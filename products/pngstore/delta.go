// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func (Adapter) Build(input engine.DomainInput, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainDelta, error) {
	request, err := decode(input)
	if err != nil {
		return engine.DomainDelta{}, err
	}
	all, err := records(owned, view)
	if err != nil {
		return engine.DomainDelta{}, err
	}
	request, _, err = deriveCarriers(request, all)
	if err != nil {
		return engine.DomainDelta{}, err
	}
	request, err = applicationDefaults(request, owned)
	if err != nil {
		return engine.DomainDelta{}, err
	}
	if err = validateTransaction(request, all, owned); err != nil {
		return engine.DomainDelta{}, err
	}
	delta := engine.DomainDelta{}
	changed := []Record{}
	for _, mutation := range request.Mutations {
		if !validIdentity(mutation.Family, owned.Bounds.MaxIdentifierBytes) || !validIdentity(mutation.Key, owned.Bounds.MaxIdentifierBytes) {
			return engine.DomainDelta{}, fmt.Errorf("bounded canonical identity required")
		}
		record, err := applyMutation(mutation, all, owned, view, &delta)
		if err != nil {
			return engine.DomainDelta{}, err
		}
		record.Data = maskedData(record.Data, mutationResultFields(mutation))
		changed = append(changed, record)
	}
	delta.ProductIntent, err = engine.CanonicalDomainJSON(map[string]interface{}{"records": changed, "result": request.Result})
	return delta, err
}
func validateTransaction(request Request, all []Record, owned engine.DomainOwnedScope) error {
	if len(request.Mutations) == 0 || len(request.Mutations) > owned.Bounds.MaxChanges {
		return fmt.Errorf("bounded nonempty native transaction required")
	}
	seen := map[string]bool{}
	for _, mutation := range request.Mutations {
		key := mutation.Family + "\x00" + mutation.Key
		if mutation.Family == "" || mutation.Key == "" || seen[key] {
			return fmt.Errorf("native mutation identity/account mismatch")
		}
		if mutation.Data["account_id"] != nil && mutation.Data["account_id"] != owned.Binding.AccountID {
			return fmt.Errorf("native mutation foreign account")
		}
		if mutation.Data["id"] != nil && mutation.Data["id"] != mutation.Key {
			return fmt.Errorf("canonical ID cannot be rebound through values")
		}
		if mutation.NativeID == "" && mutation.Data["account_id"] != owned.Binding.AccountID {
			return fmt.Errorf("native creation account required")
		}
		seen[key] = true
		if err := validateAssociateMutation(mutation, owned); err != nil {
			return err
		}
		if err := checkMutation(mutation, all); err != nil {
			return err
		}
	}
	for _, reference := range request.References {
		if err := checkReference(reference, all); err != nil {
			return err
		}
	}
	for _, unique := range request.Unique {
		if err := checkUnique(unique, all, seen, request.Mutations); err != nil {
			return err
		}
	}
	return nil
}
func checkMutation(mutation Mutation, all []Record) error {
	current, present := find(all, mutation.Family, mutation.Key)
	if !present && (mutation.NativeID != "" || mutation.ExpectedVersion != "") {
		return fmt.Errorf("existing native alias absent")
	}
	if present && (mutation.NativeID != current.NativeID || mutation.ExpectedVersion != current.Version) {
		return fmt.Errorf("explicit native alias/version CAS denied")
	}
	return nil
}
func checkReference(reference Reference, all []Record) error {
	current, present := find(all, reference.Family, reference.Key)
	if !present || current.NativeID != reference.NativeID || current.Version != reference.Version {
		return fmt.Errorf("current native reference/version mismatch")
	}
	if reference.Subtype != nil && current.Data["type"] != *reference.Subtype {
		return fmt.Errorf("native reference subtype mismatch")
	}
	return nil
}
func checkUnique(unique Unique, all []Record, changed map[string]bool, mutations []Mutation) error {
	if unique.Family == "" || len(unique.Fields) == 0 {
		return fmt.Errorf("explicit uniqueness fields required")
	}
	for _, record := range all {
		if record.Family != unique.Family || changed[record.Family+"\x00"+record.Key] {
			continue
		}
		if matchesFields(record.Data, unique.Fields) {
			return fmt.Errorf("native uniqueness conflict")
		}
	}
	return checkCandidateUnique(unique, all, mutations)
}
func checkCandidateUnique(unique Unique, all []Record, mutations []Mutation) error {
	count := 0
	for _, mutation := range mutations {
		if mutation.Family != unique.Family {
			continue
		}
		data := mutation.Data
		if current, present := find(all, mutation.Family, mutation.Key); mutation.Patch && present {
			data = mergedData(current.Data, data)
		}
		if matchesFields(data, unique.Fields) {
			count++
		}
	}
	if count > 1 {
		return fmt.Errorf("atomic native candidate uniqueness conflict")
	}
	return nil
}
func matchesFields(data, fields map[string]interface{}) bool {
	for key, value := range fields {
		if !same(data[key], value) {
			return false
		}
	}
	return true
}
func applyMutation(mutation Mutation, all []Record, owned engine.DomainOwnedScope, view engine.DomainView, delta *engine.DomainDelta) (Record, error) {
	id := mutation.NativeID
	if mutation.Patch {
		current, present := find(all, mutation.Family, mutation.Key)
		if !present {
			return Record{}, fmt.Errorf("patch target absent")
		}
		mutation.Data = mergedData(current.Data, mutation.Data)
	}
	if id == "" {
		var err error
		id, err = view.AllocateID()
		if err != nil {
			return Record{}, err
		}
	}
	record := Record{Family: mutation.Family, Key: mutation.Key, NativeID: id, Version: hash([]interface{}{mutation.ExpectedVersion, mutation.Data}), Data: mutation.Data}
	metadata, err := mutationMetadata(record, mutation, owned)
	if err != nil {
		return Record{}, err
	}
	if mutation.NativeID != "" {
		addWrites(delta, id, metadata)
		return record, nil
	}
	kind := mutationKind(mutation, owned)
	acl, err := view.CreateACL(kind)
	if err != nil {
		return Record{}, err
	}
	metadata[view.ACLMetadataKey] = acl
	delta.Creates = append(delta.Creates, engine.DomainCreate{ID: id, ParentID: owned.Binding.RootID, Kind: owned.Layout.Kinds[kind], Name: record.Key, Metadata: metadata})
	return record, nil
}
func addWrites(delta *engine.DomainDelta, id string, metadata map[string]interface{}) {
	for key, value := range metadata {
		delta.Writes = append(delta.Writes, engine.DomainWrite{NodeID: id, Key: key, Value: value})
	}
}
func mergedData(current, patch map[string]interface{}) map[string]interface{} {
	result := map[string]interface{}{}
	for key, value := range current {
		result[key] = value
	}
	for key, value := range patch {
		result[key] = value
	}
	return result
}
func mutationResultFields(mutation Mutation) []string {
	fields := []string{"account_id", "id"}
	for key := range mutation.Data {
		fields = append(fields, key)
	}
	return fields
}
