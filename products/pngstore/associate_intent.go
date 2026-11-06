// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func storeSemanticKind(record Record, owned engine.DomainOwnedScope, view engine.DomainView) (string, error) {
	native := view.Records[record.NativeID]
	if native.Kind == owned.Layout.Kinds["png_record"] {
		return "png_record", nil
	}
	if owned.Layout.AssociateCarrier != nil && record.Family == AssociateFamily && native.Kind == owned.Layout.Kinds["associate"] {
		return "associate", nil
	}
	return "", fmt.Errorf("record alias lacks actual native store resource kind")
}

func storeBaseFields(ceiling []string, owned engine.DomainOwnedScope) []string {
	fields := baseStoreFields(ceiling)
	if owned.Layout.AssociateCarrier == nil {
		return fields
	}
	result := []string{}
	for _, name := range fields {
		if name != "accountId" && name != "label" && name != "roleIds" {
			result = append(result, name)
		}
	}
	return result
}

func associateIntentFields(request Request, id, root string, owned engine.DomainOwnedScope) []string {
	fields := []string{}
	for _, mutation := range request.Mutations {
		if mutationKind(mutation, owned) == "associate" && (mutation.NativeID == id || id == root && mutation.NativeID == "") {
			fields = append(fields, associateMutationFields(mutation)...)
		}
	}
	return fields
}

func associateMutationFields(mutation Mutation) []string {
	fields := []string{"accountId", "label"}
	if mutation.NativeID == "" {
		fields = append(fields, "roleIds")
	}
	return fields
}

func associatePublicField(owned engine.DomainOwnedScope, key string) string {
	for _, name := range []string{"accountId", "label", "roleIds"} {
		if field(owned, name) == key {
			return name
		}
	}
	return ""
}
