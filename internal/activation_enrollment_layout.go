// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"sort"
)

var enrollmentKinds = []string{"root", "associate", "role", "requirement", "function", "record", "category", "association"}
var enrollmentActions = []string{"read", "role.define", "requirement.define", "function.define", "associate.role.attach", "associate.role.detach", "role.requirement.attach", "role.function.attach", "context.record.define", "context.category.define", "item.context.link", "role.template.copy", "role.update", "role.reorder", "associate.principal.link", "associate.principal.unlink"}

func validateEnrollmentLayout(p DomainProvisioningProfile, config DomainConfig) error {
	if err := enrollmentMappedNames(p.Layout.Kinds, enrollmentKinds, p.Bounds.MaxIdentifierBytes, ""); err != nil {
		return err
	}
	for _, kind := range p.Layout.Kinds {
		if kind == p.AccountRootKind {
			return fmt.Errorf("formalentity account root must be distinct from business kinds")
		}
	}
	fields := []string{"accountId", "kind", "label", "roleIds", "requirementIds", "functionIds", "contextLinks", "defaultKey", "roleOrder", "roleCatalogRef"}
	if err := enrollmentMappedNames(p.Layout.Fields, fields, p.Bounds.MaxIdentifierBytes, config.ACLMetadataKey); err != nil {
		return err
	}
	var catalog map[string]interface{}
	if len(config.RoleCatalog) == 0 || len(config.RoleCatalog) > config.MaxRequestBytes || DecodeDomainJSON(config.RoleCatalog, &catalog) != nil || catalog == nil {
		return fmt.Errorf("bounded valid protected default catalog required")
	}
	for _, operation := range enrollmentActions {
		if len(p.Layout.Profiles[operation]) == 0 {
			return fmt.Errorf("complete explicit enrollment action profiles required: %s", operation)
		}
	}
	if err := validateEnrollmentProfiles(p, config); err != nil {
		return err
	}
	if err := validateEnrollmentAssociateCarrier(p, config); err != nil {
		return err
	}
	return validateEnrollmentOwnerGrants(p, config)
}

func enrollmentMappedNames(mapping map[string]string, required []string, maximum int, forbidden string) error {
	for _, key := range required {
		if mapping[key] == "" {
			return fmt.Errorf("required protected layout mapping absent: %s", key)
		}
	}
	seen := map[string]bool{}
	for key, name := range mapping {
		if err := enrollmentIdentifiers(maximum, key, name); err != nil {
			return err
		}
		if name == forbidden || seen[name] || name == "*" {
			return fmt.Errorf("duplicate/wildcard/ACL layout mapping denied")
		}
		seen[name] = true
	}
	return nil
}

func validateEnrollmentProfiles(p DomainProvisioningProfile, config DomainConfig) error {
	for operation, profiles := range p.Layout.Profiles {
		route := p.Layout.Routes[operation]
		if err := enrollmentIdentifiers(p.Bounds.MaxIdentifierBytes, operation, route.Method, route.Target); err != nil {
			return err
		}
		if len(profiles) == 0 || len(profiles) > config.MaxResources {
			return fmt.Errorf("finite complete protected field profiles required")
		}
		if err := validateEnrollmentProfileFields(p, config, profiles); err != nil {
			return err
		}
	}
	for kind := range p.Layout.Kinds {
		if len(p.Layout.Profiles["read"][kind]) == 0 {
			return fmt.Errorf("every known native kind needs explicit read profile")
		}
	}
	return nil
}

func validateEnrollmentProfileFields(p DomainProvisioningProfile, config DomainConfig, profiles map[string][]string) error {
	for kind, fields := range profiles {
		if p.Layout.Kinds[kind] == "" {
			return fmt.Errorf("profile references unknown native kind")
		}
		if err := enrollmentUniqueFields(fields, config.MaxFields, p.Bounds.MaxIdentifierBytes); err != nil {
			return err
		}
	}
	return nil
}

func enrollmentUniqueFields(fields []string, maximum, identifierBytes int) error {
	if len(fields) == 0 || len(fields) > maximum {
		return fmt.Errorf("nonempty finite explicit enrollment fields required")
	}
	seen := map[string]bool{}
	for _, field := range fields {
		if enrollmentIdentifiers(identifierBytes, field) != nil || seen[field] || field == "*" {
			return fmt.Errorf("duplicate/invalid/wildcard enrollment field")
		}
		seen[field] = true
	}
	return nil
}

func validateEnrollmentOwnerGrants(p DomainProvisioningProfile, config DomainConfig) error {
	if len(p.OwnerGrants) != len(p.Layout.Kinds) {
		return fmt.Errorf("complete per-kind owner ACL templates required")
	}
	for kind, grants := range p.OwnerGrants {
		if p.Layout.Kinds[kind] == "" || len(grants) == 0 {
			return fmt.Errorf("unknown/empty owner template")
		}
		if err := validateEnrollmentKindGrants(p, config, kind, grants); err != nil {
			return err
		}
	}
	for operation, profiles := range p.Layout.Profiles {
		if err := validateEnrollmentOwnerCoverage(p, operation, profiles); err != nil {
			return err
		}
	}
	return nil
}

func validateEnrollmentOwnerCoverage(p DomainProvisioningProfile, operation string, profiles map[string][]string) error {
	for kind, fields := range profiles {
		if !enrollmentFieldEquality(p.OwnerGrants[kind][operation].Fields, fields) {
			return fmt.Errorf("owner template must cover exact declared action fields")
		}
	}
	return nil
}

func validateEnrollmentKindGrants(p DomainProvisioningProfile, config DomainConfig, kind string, grants map[string]domainGrant) error {
	for operation, grant := range grants {
		if enrollmentIdentifiers(p.Bounds.MaxIdentifierBytes, operation) != nil || grant.TargetGrantRevision != "" {
			return fmt.Errorf("owner defaults cannot carry target authority")
		}
		if err := enrollmentUniqueFields(grant.Fields, config.MaxFields, p.Bounds.MaxIdentifierBytes); err != nil {
			return err
		}
		if err := validateEnrollmentGrantScope(p, kind, operation, grant); err != nil {
			return err
		}
	}
	if kind == "root" {
		return validateEnrollmentRootGrants(grants)
	}
	return nil
}

func validateEnrollmentGrantScope(p DomainProvisioningProfile, kind, operation string, grant domainGrant) error {
	if operation == EnrollmentProvision || operation == EnrollmentReadGrant || operation == EnrollmentReadRevoke {
		if kind != "root" || !domainEqual(grant.Fields, []string{"acl"}) || grant.Reference || len(grant.CreateKinds) != 0 {
			return fmt.Errorf("enrollment control is root ACL-only, never data/template authority")
		}
		return nil
	}
	if !enrollmentFieldEquality(grant.Fields, p.Layout.Profiles[operation][kind]) || domainContains(grant.Fields, "reference") && !grant.Reference {
		return fmt.Errorf("owner grant must exactly match explicit field/reference profile")
	}
	seen := map[string]bool{}
	for _, created := range grant.CreateKinds {
		if kind != "root" || created == "root" || p.Layout.Kinds[created] == "" || seen[created] {
			return fmt.Errorf("explicit same-profile unique create template required")
		}
		seen[created] = true
	}
	return nil
}

func validateEnrollmentRootGrants(grants map[string]domainGrant) error {
	for _, operation := range []string{EnrollmentProvision, EnrollmentReadGrant, EnrollmentReadRevoke} {
		if !domainEqual(grants[operation].Fields, []string{"acl"}) {
			return fmt.Errorf("all explicit owner root enrollment grants required")
		}
	}
	return nil
}

func enrollmentFieldEquality(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return domainEqual(a, b)
}
