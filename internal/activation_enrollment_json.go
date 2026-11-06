// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

func enrollmentShape(raw []byte, required, optional, nullable []string) (map[string]json.RawMessage, error) {
	var shape map[string]json.RawMessage
	if err := DecodeDomainJSON(raw, &shape); err != nil {
		return nil, err
	}
	for _, key := range required {
		value, present := shape[key]
		if !present || enrollmentNull(value) && !domainContains(nullable, key) {
			return nil, fmt.Errorf("required enrollment field absent/null: %s", key)
		}
	}
	for key := range shape {
		if !domainContains(required, key) && !domainContains(optional, key) {
			return nil, fmt.Errorf("unspecified enrollment field: %s", key)
		}
	}
	return shape, nil
}

func enrollmentNull(raw []byte) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

func enrollmentIdentifiers(maximum int, values ...string) error {
	for _, value := range values {
		if maximum <= 0 || value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("invalid/bounded enrollment identifier")
		}
	}
	return nil
}

func (r *EnrollmentRequest) UnmarshalJSON(raw []byte) error {
	keys := []string{"contractRevision", "scope", "commandId", "expectedRevision", "operation", "targetPrincipalId", "profileRef"}
	keys = enrollmentAdministrationKeys(raw, keys, "administration")
	shape, err := enrollmentShape(raw, keys, nil, []string{"targetPrincipalId"})
	if err != nil {
		return err
	}
	if _, err = enrollmentShape(shape["scope"], []string{"accountId", "product"}, nil, nil); err != nil {
		return err
	}
	if _, err = enrollmentShape(shape["profileRef"], []string{"profileId", "profileRevision", "profileDigest"}, nil, nil); err != nil {
		return err
	}
	type plain EnrollmentRequest
	return DecodeDomainJSON(raw, (*plain)(r))
}

func DecodeEnrollmentInput(raw []byte, maximum int) (EnrollmentInput, error) {
	var input EnrollmentInput
	if maximum <= 0 || len(raw) == 0 || len(raw) > maximum {
		return input, fmt.Errorf("bounded enrollment input required")
	}
	keys := []string{"contractRevision", "requestId", "proof", "request"}
	if _, err := enrollmentShape(raw, keys, nil, nil); err != nil {
		return input, err
	}
	if err := DecodeDomainJSON(raw, &input); err != nil {
		return input, err
	}
	if input.ContractRevision != enrollmentProofRevision(input.Request) || !domainOpaqueProof.MatchString(input.Proof) {
		return input, fmt.Errorf("replacement enrollment revision/opaque proof required")
	}
	if err := enrollmentIdentifiers(maximum, input.RequestID, input.Proof); err != nil {
		return input, err
	}
	_, err := canonicalEnrollmentRequest(input.Request, maximum)
	return input, err
}

func CanonicalEnrollmentRequest(request EnrollmentRequest, maximum int) ([]byte, error) {
	return canonicalEnrollmentRequest(request, maximum)
}

func canonicalEnrollmentRequest(request EnrollmentRequest, maximum int) ([]byte, error) {
	if err := validateEnrollmentRequest(request, maximum); err != nil {
		return nil, err
	}
	raw, err := CanonicalDomainJSON(request)
	if err != nil || len(raw) > maximum {
		return nil, fmt.Errorf("canonical enrollment request exceeds bound")
	}
	return raw, nil
}

func validateEnrollmentRequest(r EnrollmentRequest, maximum int) error {
	if (r.ContractRevision != EnrollmentRevision && r.ContractRevision != EnrollmentAdminRevision) || r.Scope.Product != "manifest" || !domainValidHash(r.ProfileRef.ProfileDigest) {
		return fmt.Errorf("exact enrollment revision/scope/profile required")
	}
	if err := enrollmentIdentifiers(maximum, r.Scope.AccountID, r.CommandID, r.Operation, r.ProfileRef.ProfileID, r.ProfileRef.ProfileRevision); err != nil {
		return err
	}
	if err := validateEnrollmentAdministrationRequest(r, maximum); err != nil {
		return err
	}
	if r.Operation == EnrollmentProvision {
		if r.ExpectedRevision != "absent" || r.TargetPrincipalID != nil {
			return fmt.Errorf("provision requires absence CAS and explicit null target")
		}
		return nil
	}
	if r.Operation != EnrollmentReadGrant && r.Operation != EnrollmentReadRevoke && !isEnrollmentWorkloadOperation(r.Operation) {
		return fmt.Errorf("unsupported enrollment operation")
	}
	if !validEnrollmentOwnedRevision(r.ExpectedRevision) || r.TargetPrincipalID == nil {
		return fmt.Errorf("ACL enrollment requires owned CAS and explicit target")
	}
	return enrollmentIdentifiers(maximum, *r.TargetPrincipalID)
}

func validEnrollmentOwnedRevision(revision string) bool {
	const prefix = "lj.owned/v1:"
	return strings.HasPrefix(revision, prefix) && domainValidHash(strings.TrimPrefix(revision, prefix))
}

func enrollmentReferenceShape(raw []byte) error {
	keys := []string{"actorPrincipalId", "actorSessionId", "accountId", "principalId", "purpose", "requestId", "actorGrantRevision", "targetGrantRevision", "evidenceRevision", "authorityPolicyRevision", "checkedAt", "validUntil", "targetEligibility"}
	_, err := enrollmentShape(raw, keys, nil, []string{"targetGrantRevision"})
	return err
}

func enrollmentLeaseShape(raw []byte) error {
	keys := []string{"epoch", "leaseId", "principalId", "sessionId", "scope", "binding", "intentFingerprint"}
	shape, err := enrollmentShape(raw, keys, nil, nil)
	if err != nil {
		return err
	}
	if _, err = enrollmentShape(shape["scope"], []string{"accountId", "product"}, nil, nil); err != nil {
		return err
	}
	binding, err := enrollmentShape(shape["binding"], []string{"scope", "rootId", "bindingRevision"}, nil, nil)
	if err != nil {
		return err
	}
	_, err = enrollmentShape(binding["scope"], []string{"accountId", "product"}, nil, nil)
	return err
}
