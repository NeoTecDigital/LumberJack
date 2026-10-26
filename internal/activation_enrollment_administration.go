// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// Administration is an explicit immutable authorization, never an owner claim.
type EnrollmentAdministration struct {
	OwnerPrincipalID    string                            `json:"ownerPrincipalId"`
	Name                string                            `json:"name"`
	AuthorizationID     string                            `json:"authorizationId"`
	AuthorizationDigest string                            `json:"authorizationDigest"`
	Grants              map[string]map[string]domainGrant `json:"grants"`
}

var enrollmentAuthorizationUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (a *EnrollmentAdministration) UnmarshalJSON(raw []byte) error {
	keys := []string{"ownerPrincipalId", "name", "authorizationId", "authorizationDigest", "grants"}
	shape, err := enrollmentShape(raw, keys, nil, nil)
	if err != nil {
		return err
	}
	if err = enrollmentProfileGrantEncoding(shape["grants"]); err != nil {
		return err
	}
	type plain EnrollmentAdministration
	if err = DecodeDomainJSON(raw, (*plain)(a)); err != nil {
		return err
	}
	return validateEnrollmentAdministrationShape(a, len(raw))
}

func enrollmentAdministrationKeys(raw []byte, keys []string, extra string) []string {
	var shape struct {
		ContractRevision string `json:"contractRevision"`
	}
	// This preliminary read selects grammar only; the closed decoder follows.
	_ = json.Unmarshal(raw, &shape)
	if shape.ContractRevision == EnrollmentAdminRevision || shape.ContractRevision == EnrollmentAdminProofRevision {
		return append(keys, extra)
	}
	return keys
}

func enrollmentProofRevision(request EnrollmentRequest) string {
	if request.ContractRevision == EnrollmentAdminRevision {
		return EnrollmentAdminProofRevision
	}
	return EnrollmentProofRevision
}

func enrollmentRecordRevision(request EnrollmentRequest) string {
	if request.ContractRevision == EnrollmentAdminRevision {
		return EnrollmentAdminRecordRevision
	}
	return EnrollmentRecordRevision
}

func enrollmentActorAuthorized(actor EnrollmentVerified) bool {
	if actor.Kind != "human" {
		return false
	}
	if actor.Request.ContractRevision == EnrollmentAdminRevision {
		return actor.Request.Administration != nil && !actor.OwnerAuthorized && actor.AdministratorAuthorized
	}
	return actor.Request.ContractRevision == EnrollmentRevision && actor.OwnerAuthorized && !actor.AdministratorAuthorized
}

func validateEnrollmentAdministrationRequest(r EnrollmentRequest, maximum int) error {
	a := r.Administration
	if r.ContractRevision == EnrollmentRevision {
		if a != nil {
			return fmt.Errorf("legacy owner enrollment cannot contain administration")
		}
		return nil
	}
	if a == nil || r.Operation != EnrollmentProvision {
		return fmt.Errorf("administrator enrollment requires explicit provision authorization")
	}
	if enrollmentIdentifiers(maximum, a.OwnerPrincipalID) != nil || enrollmentIdentifiers(256, a.Name) != nil {
		return fmt.Errorf("bounded explicit native owner/name required")
	}
	if !enrollmentAuthorizationUUID.MatchString(a.AuthorizationID) || !domainValidHash(a.AuthorizationDigest) {
		return fmt.Errorf("canonical authorization UUID/digest required")
	}
	return validateEnrollmentAdministrationShape(a, maximum)
}

func validateEnrollmentAdministrationGrants(a *EnrollmentAdministration, p *DomainProvisioningProfile) error {
	if a == nil {
		return nil
	}
	for kind, grants := range a.Grants {
		owner, present := p.OwnerGrants[kind]
		if !present || kind == "*" || len(grants) == 0 || len(grants) > len(owner) {
			return fmt.Errorf("unknown/empty/unbounded administrator kind grants")
		}
		if err := validateEnrollmentAdministratorKind(grants, owner, p.Bounds.MaxIdentifierBytes); err != nil {
			return err
		}
	}
	return nil
}

func validateEnrollmentAdministratorKind(grants, owner map[string]domainGrant, maximum int) error {
	for operation, grant := range grants {
		bound, present := owner[operation]
		if !present || operation == "*" || grant.TargetGrantRevision != "" || grant.Reference && !bound.Reference {
			return fmt.Errorf("administrator operation/reference exceeds protected owner profile")
		}
		if enrollmentUniqueFields(grant.Fields, len(bound.Fields), maximum) != nil || !enrollmentGrantSubset(grant.Fields, bound.Fields) {
			return fmt.Errorf("administrator fields exceed protected owner profile")
		}
		if len(grant.CreateKinds) > 0 && (enrollmentUniqueFields(grant.CreateKinds, len(bound.CreateKinds), maximum) != nil || !enrollmentGrantSubset(grant.CreateKinds, bound.CreateKinds)) {
			return fmt.Errorf("administrator create kinds exceed protected owner profile")
		}
	}
	return nil
}

func enrollmentGrantSubset(values, bound []string) bool {
	for _, value := range values {
		if !domainContains(bound, value) {
			return false
		}
	}
	return true
}

func validateEnrollmentAdministrationShape(a *EnrollmentAdministration, maximum int) error {
	if len(a.Grants) == 0 {
		return fmt.Errorf("nonempty explicit administrator grants required")
	}
	for kind, grants := range a.Grants {
		if kind == "*" || enrollmentIdentifiers(maximum, kind) != nil || len(grants) == 0 {
			return fmt.Errorf("nonempty explicit administrator kind required")
		}
		if err := validateEnrollmentAdministrationOperations(grants, maximum); err != nil {
			return err
		}
	}
	return nil
}

func validateEnrollmentAdministrationOperations(grants map[string]domainGrant, maximum int) error {
	for operation, grant := range grants {
		if operation == "*" || enrollmentIdentifiers(maximum, operation) != nil || grant.TargetGrantRevision != "" {
			return fmt.Errorf("explicit administrator operation required without target claim")
		}
		if enrollmentUniqueFields(grant.Fields, maximum, maximum) != nil {
			return fmt.Errorf("explicit administrator fields required")
		}
		if len(grant.CreateKinds) > 0 && enrollmentUniqueFields(grant.CreateKinds, maximum, maximum) != nil {
			return fmt.Errorf("explicit administrator create kinds required")
		}
	}
	return nil
}
