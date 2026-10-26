// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package manifest

import (
	"fmt"
	"sort"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func (Adapter) Project(requestID string, intent engine.DomainIntent, owned engine.DomainOwnedScope, view engine.DomainView) ([]byte, error) {
	if err := authorizeProjectionFields(intent, view.Records[owned.Binding.RootID], "root"); err != nil {
		return nil, err
	}
	if err := validateGraph(owned, view); err != nil {
		return nil, err
	}
	graph := map[string]interface{}{"accountId": owned.Binding.AccountID, "revision": view.Revision, "hasMore": false}
	for _, key := range []string{"associates", "roles", "requirements", "functions", "records", "categories"} {
		graph[key] = []interface{}{}
	}
	ids := make([]string, 0, len(view.Records))
	for id := range view.Records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		record := view.Records[id]
		kind := semanticKind(owned, record.Kind)
		if kind == "root" {
			continue
		}
		if err := authorizeProjectionFields(intent, record, kind); err != nil {
			return nil, err
		}
		dto, err := projectRecord(record, kind, owned)
		if err != nil {
			return nil, err
		}
		key := graphKey(kind)
		graph[key] = append(graph[key].([]interface{}), dto)
	}
	return engine.CanonicalDomainJSON(map[string]interface{}{"contractRevision": Revision, "requestId": requestID, "scope": intent.Scope, "graph": graph})
}

func authorizeProjectionFields(intent engine.DomainIntent, record engine.DomainRecord, kind string) error {
	for _, set := range intent.Fields {
		if set.Resource.ResourceID != record.ID {
			continue
		}
		required := append([]string{"id"}, publicRecordFields(kind)...)
		return requireFields(set.Fields, required)
	}
	return fmt.Errorf("projected resource lacks explicit intent")
}

func requireFields(allowed, required []string) error {
	for _, field := range required {
		if !contains(allowed, field) {
			return fmt.Errorf("required DTO field lacks explicit intent permission")
		}
	}
	return nil
}
func projectRecord(record engine.DomainRecord, kind string, owned engine.DomainOwnedScope) (map[string]interface{}, error) {
	dto := map[string]interface{}{"id": record.ID}
	for _, field := range publicRecordFields(kind) {
		value, present := record.Metadata[owned.Layout.Fields[field]]
		if field == "defaultKey" && !present {
			continue
		}
		if !present {
			return nil, fmt.Errorf("required native public field absent")
		}
		dto[field] = value
	}
	return dto, nil
}
func publicRecordFields(kind string) []string {
	switch kind {
	case "root":
		// Native virtual projection authority, not metadata keys or inferred ACL semantics.
		return []string{"accountId", "revision", "hasMore", "associates", "roles", "requirements", "functions", "records", "categories"}
	case "associate":
		return []string{"accountId", "label", "roleIds"}
	case "role":
		return []string{"accountId", "label", "requirementIds", "functionIds", "defaultKey"}
	case "requirement", "function":
		return []string{"accountId", "label", "contextLinks"}
	case "record", "category":
		return []string{"accountId", "kind", "label"}
	}
	return nil
}
func graphKey(kind string) string {
	switch kind {
	case "category":
		return "categories"
	case "associate":
		return "associates"
	case "role":
		return "roles"
	case "requirement":
		return "requirements"
	case "function":
		return "functions"
	case "record":
		return "records"
	}
	return ""
}
func validateGraph(owned engine.DomainOwnedScope, view engine.DomainView) error {
	for _, record := range view.Records {
		kind := semanticKind(owned, record.Kind)
		if kind == "root" {
			continue
		}
		if kind == "" {
			return fmt.Errorf("unmapped native record kind")
		}
		if err := validateRecord(record, kind, owned, view); err != nil {
			return err
		}
	}
	return nil
}
func validateRecord(record engine.DomainRecord, kind string, owned engine.DomainOwnedScope, view engine.DomainView) error {
	account, ok := record.Metadata[owned.Layout.Fields["accountId"]].(string)
	if !ok || account != owned.Binding.AccountID {
		return fmt.Errorf("native public account mismatch")
	}
	if _, ok := record.Metadata[owned.Layout.Fields["label"]].(string); !ok {
		return fmt.Errorf("native public label is not text")
	}
	switch kind {
	case "associate":
		return validateRefs(record, "roleIds", "role", owned, view)
	case "role":
		if err := validateRefs(record, "requirementIds", "requirement", owned, view); err != nil {
			return err
		}
		if err := validateRefs(record, "functionIds", "function", owned, view); err != nil {
			return err
		}
		return validateDefaultKey(record, owned)
	case "requirement", "function":
		return validateContexts(record, owned, view)
	case "record", "category":
		value, ok := record.Metadata[owned.Layout.Fields["kind"]].(string)
		if !ok || !contains(contextKinds, value) {
			return fmt.Errorf("native context kind invalid")
		}
	}
	return nil
}

func validateDefaultKey(record engine.DomainRecord, owned engine.DomainOwnedScope) error {
	key, present := record.Metadata[owned.Layout.Fields["defaultKey"]]
	if !present {
		return nil
	}
	value, ok := key.(string)
	if !ok || !contains([]string{"employees", "clients", "vendors"}, value) {
		return fmt.Errorf("native defaultKey invalid")
	}
	return nil
}
func validateRefs(record engine.DomainRecord, field, kind string, owned engine.DomainOwnedScope, view engine.DomainView) error {
	refs, err := referenceList(record.Metadata[owned.Layout.Fields[field]])
	if err != nil {
		return err
	}
	for _, id := range refs {
		target, present := view.Records[id]
		if !present || target.Kind != nativeKind(owned, kind) {
			return fmt.Errorf("native reference outside kind/account closure")
		}
	}
	return nil
}
func validateContexts(record engine.DomainRecord, owned engine.DomainOwnedScope, view engine.DomainView) error {
	links, err := contextList(record.Metadata[owned.Layout.Fields["contextLinks"]])
	if err != nil {
		return err
	}
	for _, ref := range links {
		target, present := view.Records[ref.TargetID]
		if !present || target.Kind != nativeKind(owned, ref.Mode) || target.Metadata[owned.Layout.Fields["kind"]] != ref.Kind {
			return fmt.Errorf("native SPPO reference outside exact closure/kind")
		}
	}
	return nil
}
