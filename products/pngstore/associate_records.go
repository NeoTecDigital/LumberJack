// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"unicode/utf8"
)

func storeRecordKind(native engine.DomainRecord, owned engine.DomainOwnedScope) (bool, error) {
	if native.Kind == owned.Layout.Kinds["png_record"] {
		if owned.Layout.AssociateCarrier != nil && native.Metadata[field(owned, "pngFamily")] == AssociateFamily {
			return false, fmt.Errorf("legacy generic Associate cannot become a native carrier")
		}
		return true, nil
	}
	return owned.Layout.AssociateCarrier != nil && native.Kind == owned.Layout.Kinds["associate"], nil
}

func validateAssociateRecord(record Record, native engine.DomainRecord, owned engine.DomainOwnedScope, view engine.DomainView) error {
	if owned.Layout.AssociateCarrier == nil || native.Kind != owned.Layout.Kinds["associate"] {
		return nil
	}
	if record.Family != AssociateFamily || record.Data["id"] != record.Key || native.Metadata[field(owned, "accountId")] != owned.Binding.AccountID {
		return fmt.Errorf("canonical Associate/native account identity mismatch")
	}
	label, err := associateLabel(record.Data, owned)
	if err != nil || native.Metadata[field(owned, "label")] != label {
		return fmt.Errorf("native Associate label projection mismatch")
	}
	return validateAssociateRoles(native.Metadata[field(owned, "roleIds")], owned, view)
}

func validateAssociateRoles(value interface{}, owned engine.DomainOwnedScope, view engine.DomainView) error {
	raw, err := engine.CanonicalDomainJSON(value)
	var ids []string
	if err != nil || engine.DecodeDomainJSON(raw, &ids) != nil || ids == nil || len(ids) > owned.Bounds.MaxNodes {
		return fmt.Errorf("bounded explicit native business Role references required")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		target, present := view.Records[id]
		if !validIdentity(id, owned.Bounds.MaxIdentifierBytes) || seen[id] || !present || target.Kind != owned.Layout.Kinds["role"] || target.Metadata[field(owned, "accountId")] != owned.Binding.AccountID {
			return fmt.Errorf("native Associate Role reference outside account/kind closure")
		}
		seen[id] = true
	}
	return nil
}

func associateLabel(data map[string]interface{}, owned engine.DomainOwnedScope) (string, error) {
	p := owned.Layout.AssociateCarrier
	value := data[p.LabelField]
	if value == nil {
		return *p.NullLabel, nil
	}
	label, ok := value.(string)
	if !ok || !utf8.ValidString(label) {
		return "", fmt.Errorf("canonical Associate label must be reviewed text/null")
	}
	return label, nil
}
