// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// Carrier policy is protected profile content, not an enrollment request option.
func enrollmentAssociateCarrierEncoding(raw json.RawMessage) error {
	keys := []string{"contractRevision", "family", "nativeKind", "labelField", "nullLabel", "initialRoleIds"}
	if _, err := enrollmentShape(raw, keys, nil, nil); err != nil {
		return err
	}
	var policy DomainAssociateCarrierPolicy
	if err := DecodeDomainJSON(raw, &policy); err != nil {
		return err
	}
	return validateEnrollmentAssociateCarrierPolicy(&policy)
}

func validateEnrollmentAssociateCarrier(p DomainProvisioningProfile, config DomainConfig) error {
	if p.Layout.AssociateCarrier == nil {
		return nil // Omitted opt-in preserves the original enrollment contract.
	}
	if err := validateEnrollmentAssociateCarrierPolicy(p.Layout.AssociateCarrier); err != nil {
		return err
	}
	if err := enrollmentMappedNames(p.Layout.Kinds, []string{"associate", "png_record"}, p.Bounds.MaxIdentifierBytes, ""); err != nil {
		return err
	}
	fields := []string{"pngKey", "pngFamily", "pngData", "pngVersion", "accountId", "label", "roleIds"}
	if err := enrollmentMappedNames(p.Layout.Fields, fields, p.Bounds.MaxIdentifierBytes, config.ACLMetadataKey); err != nil {
		return err
	}
	for _, operation := range []string{"png.store.read", "png.store.write.define"} {
		if err := enrollmentAssociateCarrierStoreProfile(p, operation); err != nil {
			return err
		}
	}
	write := "png.store.write.define"
	if !domainContains(p.OwnerGrants["root"][write].CreateKinds, "associate") {
		return fmt.Errorf("Associate carrier requires explicit root Associate creation authority")
	}
	return enrollmentCarrierFields([]string{"accountId", "label", "roleIds"}, p.Layout.Profiles[write]["root"])
}

func validateEnrollmentAssociateCarrierPolicy(p *DomainAssociateCarrierPolicy) error {
	if p == nil || p.ContractRevision != "manifest-associate-carrier/0.1" || p.Family != "business:associate" || p.NativeKind != "associate" || p.LabelField != "full_name" {
		return fmt.Errorf("explicit reviewed Associate carrier contract required")
	}
	if p.NullLabel == nil || !utf8.ValidString(*p.NullLabel) || p.InitialRoleIDs == nil || len(p.InitialRoleIDs) != 0 {
		return fmt.Errorf("explicit UTF-8 null label and empty initial business Roles required")
	}
	return nil
}

func enrollmentAssociateCarrierStoreProfile(p DomainProvisioningProfile, operation string) error {
	route, profiles := p.Layout.Routes[operation], p.Layout.Profiles[operation]
	if route.Method != "POST" || route.Target == "" {
		return fmt.Errorf("explicit Associate carrier native store route required")
	}
	for _, kind := range []string{"root", "png_record", "associate"} {
		if len(profiles[kind]) == 0 || !enrollmentFieldEquality(p.OwnerGrants[kind][operation].Fields, profiles[kind]) {
			return fmt.Errorf("explicit per-kind Associate carrier store profile/template required")
		}
	}
	if err := enrollmentCarrierFields([]string{"id", "pngKey", "pngFamily", "pngData", "pngVersion"}, profiles["associate"]); err != nil {
		return err
	}
	if operation == "png.store.write.define" {
		return enrollmentCarrierFields([]string{"accountId", "label", "roleIds"}, profiles["associate"])
	}
	return nil
}

func enrollmentCarrierFields(required, profile []string) error {
	for _, field := range required {
		if !domainContains(profile, field) {
			return fmt.Errorf("Associate carrier required native store field absent: %s", field)
		}
	}
	return nil
}
