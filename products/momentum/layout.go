// Written by Richard Christopher, Copyright 2026 Mindfull
package momentum

import (
	"fmt"
	"sort"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func ValidateLayout(owned engine.DomainOwnedScope, aclKey string) error {
	layout := owned.Layout
	if layout.ContractRevision != Revision || owned.Binding.ProductID != "momentum" || len(layout.Kinds) != 2 {
		return fmt.Errorf("explicit Momentum layout required")
	}
	if !text(layout.Kinds["root"], 200, false) || !text(layout.Kinds["work"], 200, false) || layout.Kinds["root"] == layout.Kinds["work"] {
		return fmt.Errorf("distinct native workspace kinds required")
	}
	if err := validateMappings(layout, aclKey); err != nil {
		return err
	}
	for _, operation := range Operations {
		if layout.Routes[operation] != route(operation) || len(layout.Profiles[operation]) != 2 {
			return fmt.Errorf("exact workspace routes and profiles required")
		}
		for _, kind := range []string{"root", "work"} {
			if !sameFields(layout.Profiles[operation][kind], profile(kind)) {
				return fmt.Errorf("exact workspace field profile required")
			}
		}
	}
	return nil
}

func validateMappings(layout engine.DomainLayout, aclKey string) error {
	if len(layout.Fields) != len(Fields) || len(layout.Routes) != len(Operations) || len(layout.Profiles) != len(Operations) {
		return fmt.Errorf("closed workspace layout required")
	}
	used := map[string]bool{aclKey: true}
	for _, field := range Fields {
		value := layout.Fields[field]
		if !text(value, 200, false) || used[value] {
			return fmt.Errorf("unique public workspace fields required")
		}
		used[value] = true
	}
	return nil
}

func route(operation string) engine.DomainRoute {
	if operation == "read" {
		return engine.DomainRoute{Method: "GET", Target: "/api/workspace"}
	}
	return engine.DomainRoute{Method: "POST", Target: "/api/workspace/commands"}
}

func profile(kind string) []string {
	fields := append([]string{"id", "children", "permission"}, Fields...)
	sort.Strings(fields)
	return fields
}

func sameFields(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	copy := append([]string(nil), left...)
	sort.Strings(copy)
	for index := range copy {
		if copy[index] != right[index] {
			return false
		}
	}
	return true
}

func (Adapter) PublicFields(kind string, keys []string, owned engine.DomainOwnedScope) ([]string, error) {
	if kind != owned.Layout.Kinds["root"] && kind != owned.Layout.Kinds["work"] {
		return nil, fmt.Errorf("unmapped workspace kind")
	}
	reverse := map[string]string{"children": "children"}
	for field, key := range owned.Layout.Fields {
		reverse[key] = field
	}
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		field, exists := reverse[key]
		if !exists {
			return nil, fmt.Errorf("private workspace field refused")
		}
		result = append(result, field)
	}
	sort.Strings(result)
	return result, nil
}
