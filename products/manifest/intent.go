// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package manifest

import (
	"fmt"
	"sort"
	"strings"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func (Adapter) Resolve(input engine.DomainInput, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainIntent, error) {
	request, p, err := decode(input)
	if err != nil {
		return engine.DomainIntent{}, err
	}
	operation := request.Operation
	if input.Mode == "read" {
		operation = "read"
	}
	route, present := owned.Layout.Routes[operation]
	if !present || route.Method != input.Method || route.Target != input.Target {
		return engine.DomainIntent{}, fmt.Errorf("native intent route mismatch")
	}
	if request.Scope != (engine.DomainScope{AccountID: owned.Binding.AccountID, Product: owned.Binding.ProductID}) {
		return engine.DomainIntent{}, fmt.Errorf("native account/product mismatch")
	}
	resources, err := resolveResources(input, request, p, owned, view)
	if err != nil {
		return engine.DomainIntent{}, err
	}
	sets, err := resolveFields(operation, resources, owned)
	if err != nil {
		return engine.DomainIntent{}, err
	}
	data, err := canonicalBody(input.Body)
	if err != nil {
		return engine.DomainIntent{}, err
	}
	intent := engine.DomainIntent{ContractRevision: Revision, Scope: request.Scope, Binding: engine.DomainBinding{Scope: request.Scope, RootID: owned.Binding.RootID, BindingRevision: owned.Binding.BindingRevision}, Mode: input.Mode, Method: input.Method, Target: input.Target, RequestFingerprint: hash(data), Resources: resources, Fields: sets}
	if input.Mode == "command" {
		intent.Operation = &request.Operation
	}
	return intent, nil
}
func resolveResources(input engine.DomainInput, request envelope, p payload, owned engine.DomainOwnedScope, view engine.DomainView) ([]engine.DomainResource, error) {
	resources := map[string]engine.DomainResource{}
	if err := addResource(resources, owned.Binding.RootID, "root", owned, view); err != nil {
		return nil, err
	}
	if input.Mode == "read" {
		if err := readResources(resources, owned, view); err != nil {
			return nil, err
		}
	} else {
		if err := commandResources(resources, request.Operation, p, owned, view); err != nil {
			return nil, err
		}
	}
	result := make([]engine.DomainResource, 0, len(resources))
	for _, resource := range resources {
		result = append(result, resource)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].ResourceID < result[j].ResourceID
	})
	return result, nil
}

func readResources(resources map[string]engine.DomainResource, owned engine.DomainOwnedScope, view engine.DomainView) error {
	for id, record := range view.Records {
		if err := addResource(resources, id, semanticKind(owned, record.Kind), owned, view); err != nil {
			return err
		}
	}
	return nil
}
func commandResources(resources map[string]engine.DomainResource, operation string, p payload, owned engine.DomainOwnedScope, view engine.DomainView) error {
	switch operation {
	case "associate.role.attach", "associate.role.detach":
		if err := addResource(resources, p.AssociateID, "associate", owned, view); err != nil {
			return err
		}
		return addResource(resources, p.RoleID, "role", owned, view)
	case "role.requirement.attach", "role.function.attach":
		if err := addResource(resources, p.RoleID, "role", owned, view); err != nil {
			return err
		}
		return addResource(resources, p.ItemID, strings.TrimSuffix(strings.TrimPrefix(operation, "role."), ".attach"), owned, view)
	case "item.context.link":
		if err := addResource(resources, p.ItemID, p.ItemKind, owned, view); err != nil {
			return err
		}
		if err := addResource(resources, p.ContextLink.TargetID, p.ContextLink.Mode, owned, view); err != nil {
			return err
		}
		resource := resources[p.ContextLink.TargetID]
		if resource.ContextKind == nil || *resource.ContextKind != p.ContextLink.Kind {
			return fmt.Errorf("context reference kind mismatch")
		}
	}
	return nil
}
func addResource(resources map[string]engine.DomainResource, id, kind string, owned engine.DomainOwnedScope, view engine.DomainView) error {
	record, present := view.Records[id]
	if !present || kind == "" || record.Kind != nativeKind(owned, kind) {
		return fmt.Errorf("reference missing/wrong native kind")
	}
	resource := engine.DomainResource{AccountID: owned.Binding.AccountID, Kind: kind, ResourceID: id}
	if kind != "root" {
		account, ok := record.Metadata[owned.Layout.Fields["accountId"]].(string)
		if !ok || account != owned.Binding.AccountID {
			return fmt.Errorf("foreign native account reference")
		}
	}
	if kind == "record" || kind == "category" {
		contextKind, ok := record.Metadata[owned.Layout.Fields["kind"]].(string)
		if !ok || !contains(contextKinds, contextKind) {
			return fmt.Errorf("native context kind invalid")
		}
		resource.ContextKind = &contextKind
	}
	resources[id] = resource
	return nil
}
func resolveFields(operation string, resources []engine.DomainResource, owned engine.DomainOwnedScope) ([]engine.DomainFieldSet, error) {
	sets := make([]engine.DomainFieldSet, 0, len(resources))
	for _, resource := range resources {
		fields := owned.Layout.Profiles[operation][resource.Kind]
		if len(fields) == 0 {
			return nil, fmt.Errorf("owner intent field profile absent")
		}
		fields = append([]string(nil), fields...)
		sort.Strings(fields)
		if duplicate(fields) {
			return nil, fmt.Errorf("duplicate intent fields")
		}
		sets = append(sets, engine.DomainFieldSet{Resource: resource, Fields: fields})
	}
	return sets, nil
}
func duplicate(values []string) bool {
	for index, value := range values {
		if value == "" || index > 0 && value == values[index-1] {
			return true
		}
	}
	return false
}
