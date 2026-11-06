// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func mutationKind(mutation Mutation, owned engine.DomainOwnedScope) string {
	if owned.Layout.AssociateCarrier != nil && mutation.Family == AssociateFamily {
		return "associate"
	}
	return "png_record"
}

func validateAssociateMutation(mutation Mutation, owned engine.DomainOwnedScope) error {
	if mutationKind(mutation, owned) != "associate" {
		return nil
	}
	for _, key := range []string{"nativeKind", "native_kind", "roleIds", "role_ids", field(owned, "roleIds")} {
		if _, present := mutation.Data[key]; present {
			return fmt.Errorf("native kind and business Role assignments are not caller mutation data")
		}
	}
	return nil
}

func mutationMetadata(record Record, mutation Mutation, owned engine.DomainOwnedScope) (map[string]interface{}, error) {
	metadata := map[string]interface{}{field(owned, "pngKey"): record.Key, field(owned, "pngFamily"): record.Family,
		field(owned, "pngData"): record.Data, field(owned, "pngVersion"): record.Version}
	if mutationKind(mutation, owned) != "associate" {
		return metadata, nil
	}
	if record.Data["id"] != record.Key || record.Data["account_id"] != owned.Binding.AccountID {
		return nil, fmt.Errorf("canonical Associate identity required")
	}
	label, err := associateLabel(record.Data, owned)
	if err != nil {
		return nil, err
	}
	metadata[field(owned, "accountId")], metadata[field(owned, "label")] = owned.Binding.AccountID, label
	if mutation.NativeID == "" {
		metadata[field(owned, "roleIds")] = []string{}
	}
	return metadata, nil
}
