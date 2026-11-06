// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
)

func (p *DomainProvisioningProfile) UnmarshalJSON(raw []byte) error {
	keys := []string{"contractRevision", "profileRef", "bounds", "layout", "accountRootKind", "ownerGrants"}
	shape, err := enrollmentShape(raw, keys, nil, nil)
	if err != nil {
		return err
	}
	if _, err = enrollmentShape(shape["profileRef"], []string{"profileId", "profileRevision", "profileDigest"}, nil, nil); err != nil {
		return err
	}
	if err = enrollmentProfileEncoding(shape); err != nil {
		return err
	}
	type plain DomainProvisioningProfile
	return DecodeDomainJSON(raw, (*plain)(p))
}

func enrollmentProfileEncoding(shape map[string]json.RawMessage) error {
	boundKeys := []string{"maxNodes", "maxChanges", "maxReceipts", "maxIdentifierBytes", "maxValueDepth", "maxScopeBytes", "maxSnapshotBytes"}
	if _, err := enrollmentShape(shape["bounds"], boundKeys, nil, nil); err != nil {
		return err
	}
	layoutKeys := []string{"contractRevision", "catalogRef", "kinds", "fields", "routes", "profiles"}
	layout, err := enrollmentShape(shape["layout"], layoutKeys, []string{"applicationCreateDefaults", "associateCarrier"}, nil)
	if err != nil {
		return err
	}
	if value, present := layout["associateCarrier"]; present {
		if err = enrollmentAssociateCarrierEncoding(value); err != nil {
			return err
		}
	}
	if _, err = enrollmentShape(layout["catalogRef"], []string{"catalogId", "catalogVersion", "catalogDigest"}, nil, nil); err != nil {
		return err
	}
	if value, present := layout["applicationCreateDefaults"]; present {
		var defaults map[string][]string
		if DecodeDomainJSON(value, &defaults) != nil || len(defaults) == 0 {
			return fmt.Errorf("optional profile defaults must be omitted or nonempty")
		}
	}
	return enrollmentProfileGrantEncoding(shape["ownerGrants"])
}

func enrollmentProfileGrantEncoding(raw []byte) error {
	var kinds map[string]map[string]json.RawMessage
	if err := DecodeDomainJSON(raw, &kinds); err != nil {
		return err
	}
	for _, grants := range kinds {
		if err := enrollmentProfileKindGrantEncoding(grants); err != nil {
			return err
		}
	}
	return nil
}

func enrollmentProfileKindGrantEncoding(grants map[string]json.RawMessage) error {
	for _, grant := range grants {
		if err := enrollmentProfileOneGrantEncoding(grant); err != nil {
			return err
		}
	}
	return nil
}

func enrollmentProfileOneGrantEncoding(raw []byte) error {
	shape, err := enrollmentShape(raw, []string{"fields"}, []string{"createKinds", "reference"}, nil)
	if err != nil {
		return err
	}
	if value, present := shape["reference"]; present && string(value) != "true" {
		return fmt.Errorf("profile reference must be omitted or true")
	}
	if value, present := shape["createKinds"]; present {
		var kinds []string
		if DecodeDomainJSON(value, &kinds) != nil || len(kinds) == 0 {
			return fmt.Errorf("profile createKinds must be omitted or nonempty")
		}
	}
	return nil
}

// Digest is over the frozen canonical profile, excluding only its self digest.
func DomainProvisioningProfileDigest(profile DomainProvisioningProfile) (string, error) {
	raw, err := CanonicalDomainJSON(profile)
	if err != nil {
		return "", err
	}
	var shape map[string]interface{}
	if err = DecodeDomainJSON(raw, &shape); err != nil {
		return "", err
	}
	ref, ok := shape["profileRef"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("profile reference required")
	}
	delete(ref, "profileDigest")
	raw, err = CanonicalDomainJSON(shape)
	return stagedHash(raw), err
}

func validateDomainProvisioningProfile(config DomainConfig) error {
	p := config.ProvisioningProfile
	if p == nil {
		return nil // Legacy configured roots are unchanged; enrollment refuses nil.
	}
	if p.ContractRevision != EnrollmentProfileRevision || p.AccountRootKind != "formalentity" || p.Layout.ContractRevision != "manifest-associates/0.2" {
		return fmt.Errorf("explicit replacement formalentity/profile/layout required")
	}
	if err := validateStagedBounds(p.Bounds); err != nil {
		return err
	}
	if err := enrollmentIdentifiers(p.Bounds.MaxIdentifierBytes, p.ProfileRef.ProfileID, p.ProfileRef.ProfileRevision); err != nil {
		return err
	}
	digest, err := DomainProvisioningProfileDigest(*p)
	if err != nil || !domainValidHash(p.ProfileRef.ProfileDigest) || digest != p.ProfileRef.ProfileDigest {
		return fmt.Errorf("protected profile exact canonical digest mismatch")
	}
	raw, err := CanonicalDomainJSON(p)
	if err != nil || len(raw) > config.MaxRequestBytes {
		return fmt.Errorf("protected profile exceeds configured request bound")
	}
	return validateEnrollmentLayout(*p, config)
}

func (d *domainEngine) enrollmentProfile(request EnrollmentRequest) (*DomainProvisioningProfile, error) {
	p := d.config.ProvisioningProfile
	if p == nil || request.ProfileRef != p.ProfileRef {
		return nil, fmt.Errorf("current exact protected enrollment profile absent")
	}
	if err := validateEnrollmentRequest(request, p.Bounds.MaxIdentifierBytes); err != nil {
		return nil, err
	}
	if err := validateEnrollmentAdministrationGrants(request.Administration, p); err != nil {
		return nil, err
	}
	return p, nil
}

func enrollmentScopeID(accountID string) string {
	raw, err := CanonicalDomainJSON(accountID)
	if err != nil {
		return ""
	}
	return "manifest/enrollment/" + stagedHash(raw)
}

func (d *domainEngine) lookupDomainScope(scope DomainScope) (DomainOwnedScope, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	owned, present := d.scopes[scope]
	return owned, present
}
