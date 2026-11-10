// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
)

func coownerKeys(raw []byte, keys, additions []string) []string {
	var value struct {
		ContractRevision string `json:"contractRevision"`
	}
	_ = json.Unmarshal(raw, &value)
	if value.ContractRevision == EnrollmentCoownerRevision || value.ContractRevision == EnrollmentCoownerProofRevision || value.ContractRevision == EnrollmentCoownerRecordRevision {
		return append(keys, additions...)
	}
	return keys
}

func coownerInputKeys(raw []byte, keys []string) []string {
	keys = coownerKeys(raw, keys, []string{"mode"})
	var value struct {
		ContractRevision string `json:"contractRevision"`
		Mode             string `json:"mode"`
	}
	_ = json.Unmarshal(raw, &value)
	if value.ContractRevision == EnrollmentCoownerProofRevision && value.Mode == "inspect" {
		keys = append(keys, "receiptActorPrincipalId")
	}
	return keys
}

func validateCoownerInput(input EnrollmentInput, maximum int) error {
	if !enrollmentCoownerRequest(input.Request) {
		if input.Mode != "" || input.ReceiptActorPrincipalID != nil {
			return fmt.Errorf("legacy enrollment mode fields denied")
		}
		return nil
	}
	if input.Mode == "apply" && input.ReceiptActorPrincipalID == nil {
		return nil
	}
	if input.Mode != "inspect" || input.ReceiptActorPrincipalID == nil {
		return fmt.Errorf("co-owner apply or typed inspection required")
	}
	return enrollmentIdentifiers(maximum, *input.ReceiptActorPrincipalID)
}

func (c *EnrollmentCoownerChange) UnmarshalJSON(raw []byte) error {
	keys := []string{"founderPrincipalId", "ownershipRevision", "expectedTargetGrantRevision", "expectedCoownerGrantRevision", "ownerGrantRevision"}
	_, err := enrollmentShape(raw, keys, nil, keys[2:])
	if err != nil {
		return err
	}
	type plain EnrollmentCoownerChange
	return DecodeDomainJSON(raw, (*plain)(c))
}

func (a *EnrollmentCoownerAuthority) UnmarshalJSON(raw []byte) error {
	keys := []string{"accountKind", "commandRevision", "targetKind", "targetAccepted", "targetNativeState", "actorGrantState", "receiptAuthorized"}
	if _, err := enrollmentShape(raw, keys, nil, nil); err != nil {
		return err
	}
	type plain EnrollmentCoownerAuthority
	return DecodeDomainJSON(raw, (*plain)(a))
}

func (b *EnrollmentCoownerReceiptBinding) UnmarshalJSON(raw []byte) error {
	shape, err := enrollmentShape(raw, []string{"pair", "responseHash", "currentStateDigest"}, nil, []string{"currentStateDigest"})
	if err != nil {
		return err
	}
	if err = coownerPairShape(shape["pair"]); err != nil {
		return err
	}
	type plain EnrollmentCoownerReceiptBinding
	if err = DecodeDomainJSON(raw, (*plain)(b)); err != nil {
		return err
	}
	if !domainValidHash(b.ResponseHash) || b.CurrentStateDigest != nil && !domainValidHash(*b.CurrentStateDigest) {
		return fmt.Errorf("co-owner receipt binding hashes required")
	}
	return nil
}

func coownerPairShape(raw []byte) error {
	keys := []string{"epoch", "scopeId", "receiptKey", "nativeFingerprint", "requestFingerprint", "expectedRevision", "revision", "receiptHash", "sequence", "snapshotHash", "commandId", "principalId", "scope", "binding"}
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

func coownerProofKeys(raw []byte, keys []string) []string {
	return coownerKeys(raw, keys, []string{"coownerAuthority", "mode", "receiptActorPrincipalId", "exchangeFingerprint", "receiptBinding", "nativeHostId"})
}

func (a *domainACL) UnmarshalJSON(raw []byte) error {
	var header struct {
		ContractRevision string `json:"contractRevision"`
	}
	if json.Unmarshal(raw, &header) != nil || !coownerACLRevision(header.ContractRevision) {
		return fmt.Errorf("exact native ACL version required")
	}
	optional := []string{"createACLs"}
	if header.ContractRevision == domainCoownerACLRevision {
		optional = append(optional, "coowners")
	}
	shape, err := enrollmentShape(raw, []string{"contractRevision", "principals"}, optional, []string{"createACLs"})
	if err != nil {
		return err
	}
	if value, present := shape["coowners"]; present && enrollmentNull(value) {
		return fmt.Errorf("co-owner map cannot be null")
	}
	type plain domainACL
	if err := DecodeDomainJSON(raw, (*plain)(a)); err != nil {
		return err
	}
	return validateCoownerACL(*a)
}

func (c *domainCoownerContribution) UnmarshalJSON(raw []byte) error {
	keys := []string{"state", "grantRevision", "grantCommandId", "grantFingerprint", "profileRef", "grants"}
	shape, err := enrollmentShape(raw, keys, nil, nil)
	if err != nil {
		return err
	}
	if _, err = enrollmentShape(shape["profileRef"], []string{"profileId", "profileRevision", "profileDigest"}, nil, nil); err != nil {
		return err
	}
	var grants map[string]json.RawMessage
	if err = DecodeDomainJSON(shape["grants"], &grants); err != nil {
		return err
	}
	for _, grant := range grants {
		if _, err = enrollmentShape(grant, []string{"fields", "targetGrantRevision"}, []string{"reference", "createKinds"}, nil); err != nil {
			return err
		}
	}
	type plain domainCoownerContribution
	if err = DecodeDomainJSON(raw, (*plain)(c)); err != nil {
		return err
	}
	return validateCoownerContribution(*c)
}

func validateCoownerContribution(c domainCoownerContribution) error {
	if c.State != "installed" && c.State != "revoked" || !domainValidHash(c.GrantFingerprint) || !domainValidHash(c.ProfileRef.ProfileDigest) || c.Grants == nil {
		return fmt.Errorf("invalid co-owner contribution identity")
	}
	if enrollmentIdentifiers(4096, c.GrantRevision, c.GrantCommandID, c.ProfileRef.ProfileID, c.ProfileRef.ProfileRevision) != nil {
		return fmt.Errorf("invalid co-owner contribution revisions")
	}
	if c.State == "revoked" && len(c.Grants) != 0 {
		return fmt.Errorf("revoked contribution cannot grant")
	}
	for operation, grant := range c.Grants {
		if operation == "*" || enrollmentIdentifiers(4096, operation) != nil || grant.TargetGrantRevision != c.GrantRevision {
			return fmt.Errorf("co-owner operation must bind its generation")
		}
		if err := enrollmentUniqueFields(grant.Fields, 4096, 4096); err != nil {
			return err
		}
		if len(grant.CreateKinds) != 0 && enrollmentUniqueFields(grant.CreateKinds, 4096, 4096) != nil {
			return fmt.Errorf("invalid bounded create kinds")
		}
	}
	return nil
}

func validateCoownerACL(acl domainACL) error {
	if acl.ContractRevision == domainACLRevision && acl.Coowners != nil {
		return fmt.Errorf("co-owner contribution requires exact ACL/2")
	}
	for principal, c := range acl.Coowners {
		if enrollmentIdentifiers(4096, principal) != nil || domainWorkloadIdentity(principal, "") {
			return fmt.Errorf("human co-owner principal required")
		}
		if err := validateCoownerContribution(c); err != nil {
			return err
		}
	}
	return nil
}

func coownerACLRevisionString(raw interface{}) bool {
	value, ok := raw.(string)
	return ok && coownerACLRevision(value)
}

func coownerCreateTemplate(acl domainACL, kind, root string) (interface{}, error) {
	template, present := acl.CreateACLs[kind]
	if !present || !coownerACLRevision(template.ContractRevision) || template.Principals == nil {
		return nil, fmt.Errorf("explicit owner new-record ACL template absent")
	}
	return domainACLReferenceValue(root, kind), nil
}
