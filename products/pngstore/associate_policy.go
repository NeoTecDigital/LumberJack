// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"unicode/utf8"
)

const AssociateCarrierRevision = "manifest-associate-carrier/0.1"
const AssociateFamily = "business:associate"

func validateAssociateCarrier(owned engine.DomainOwnedScope, aclKey string) error {
	p := owned.Layout.AssociateCarrier
	if p == nil {
		return nil
	}
	if p.ContractRevision != AssociateCarrierRevision || p.Family != AssociateFamily || p.NativeKind != "associate" || p.LabelField != "full_name" {
		return fmt.Errorf("explicit reviewed Associate carrier contract required")
	}
	if p.NullLabel == nil || !utf8.ValidString(*p.NullLabel) || p.InitialRoleIDs == nil || len(p.InitialRoleIDs) != 0 {
		return fmt.Errorf("explicit null label and empty initial business Roles required")
	}
	if err := associateCarrierMappings(owned, aclKey); err != nil {
		return err
	}
	return associateCarrierProfiles(owned)
}

func associateCarrierMappings(owned engine.DomainOwnedScope, aclKey string) error {
	kind := owned.Layout.Kinds["associate"]
	if kind == "" || kind == owned.Layout.Kinds["png_record"] || kind == owned.Layout.Kinds["root"] {
		return fmt.Errorf("explicit distinct actual Associate kind required")
	}
	seen := map[string]bool{aclKey: true}
	for _, name := range []string{"pngKey", "pngFamily", "pngData", "pngVersion", "accountId", "label", "roleIds"} {
		key := field(owned, name)
		if !validIdentity(key, owned.Bounds.MaxIdentifierBytes) || seen[key] {
			return fmt.Errorf("explicit unique Associate metadata mappings required")
		}
		seen[key] = true
	}
	return nil
}

func associateCarrierProfiles(owned engine.DomainOwnedScope) error {
	for _, operation := range []string{"png.store.read", WriteOperation} {
		profile := owned.Layout.Profiles[operation]["associate"]
		if len(profile) == 0 {
			return fmt.Errorf("Associate-specific native store profile required")
		}
		if err := checkStoreCeiling([]string{"id", "pngKey", "pngFamily", "pngData", "pngVersion"}, profile); err != nil {
			return err
		}
	}
	return checkStoreCeiling([]string{"accountId", "label", "roleIds"}, owned.Layout.Profiles[WriteOperation]["associate"])
}
