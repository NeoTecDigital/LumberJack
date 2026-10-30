// Written by Richard Christopher, Copyright 2026 Mindfull
package momentum

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func (Adapter) Resolve(input engine.DomainInput, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainIntent, error) {
	request, err := decode(input)
	if err != nil {
		return engine.DomainIntent{}, err
	}
	operation := request.Operation
	if input.Mode == "read" {
		operation = "read"
	}
	expected := route(operation)
	if input.Method != expected.Method || input.Target != expected.Target || request.Scope != (engine.DomainScope{AccountID: owned.Binding.AccountID, Product: "momentum"}) {
		return engine.DomainIntent{}, fmt.Errorf("workspace intent route/scope mismatch")
	}
	ids := resourceIDs(request, owned, view)
	resources, fields, err := intentFields(ids, operation, owned, view)
	if err != nil {
		return engine.DomainIntent{}, err
	}
	var value interface{}
	if engine.DecodeDomainJSON(input.Body, &value) != nil {
		return engine.DomainIntent{}, fmt.Errorf("canonical workspace body required")
	}
	raw, err := engine.CanonicalDomainJSON(value)
	digest := sha256.Sum256(raw)
	intent := engine.DomainIntent{ContractRevision: Revision, Scope: request.Scope, Mode: input.Mode, Method: input.Method, Target: input.Target,
		Binding:            engine.DomainBinding{Scope: request.Scope, RootID: owned.Binding.RootID, BindingRevision: owned.Binding.BindingRevision},
		RequestFingerprint: hex.EncodeToString(digest[:]), Resources: resources, Fields: fields}
	if input.Mode == "command" {
		intent.Operation = &request.Operation
	}
	return intent, err
}

func resourceIDs(request envelope, owned engine.DomainOwnedScope, view engine.DomainView) []string {
	ids := map[string]bool{owned.Binding.RootID: true}
	if request.Operation == "" {
		for id := range view.Records {
			ids[id] = true
		}
	}
	for _, id := range []string{request.Payload.NodeID, request.Payload.ParentID} {
		if id != "" {
			ids[id] = true
		}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func intentFields(ids []string, operation string, owned engine.DomainOwnedScope, view engine.DomainView) ([]engine.DomainResource, []engine.DomainFieldSet, error) {
	resources := []engine.DomainResource{}
	fields := []engine.DomainFieldSet{}
	for _, id := range ids {
		_, kind, err := checkedRecord(id, owned, view)
		if err != nil {
			return nil, nil, err
		}
		resource := engine.DomainResource{AccountID: owned.Binding.AccountID, Kind: kind, ResourceID: id}
		allowed := append([]string(nil), owned.Layout.Profiles[operation][kind]...)
		sort.Strings(allowed)
		resources = append(resources, resource)
		fields = append(fields, engine.DomainFieldSet{Resource: resource, Fields: allowed})
	}
	return resources, fields, nil
}
