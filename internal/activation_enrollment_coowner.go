// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

const EnrollmentCoownerRevision = "manifest-account-enrollment/0.4"
const EnrollmentCoownerProofRevision = "manifest-native-enrollment/0.4"
const EnrollmentCoownerRecordRevision = "manifest-native-enrollment-record/0.4"
const EnrollmentCoownerGrant = "manifest.scope.coowner.grant"
const EnrollmentCoownerRevoke = "manifest.scope.coowner.revoke"
const domainCoownerACLRevision = "lj.domain.acl/2"

type EnrollmentCoownerChange struct {
	FounderPrincipalID           string  `json:"founderPrincipalId"`
	OwnershipRevision            string  `json:"ownershipRevision"`
	ExpectedTargetGrantRevision  *string `json:"expectedTargetGrantRevision"`
	ExpectedCoownerGrantRevision *string `json:"expectedCoownerGrantRevision"`
	OwnerGrantRevision           *string `json:"ownerGrantRevision"`
}

type EnrollmentCoownerAuthority struct {
	AccountKind       string `json:"accountKind"`
	CommandRevision   string `json:"commandRevision"`
	TargetKind        string `json:"targetKind"`
	TargetAccepted    bool   `json:"targetAccepted"`
	TargetNativeState string `json:"targetNativeState"`
	ActorGrantState   string `json:"actorGrantState"`
	ReceiptAuthorized bool   `json:"receiptAuthorized"`
}

type EnrollmentCoownerWire struct {
	Mode                    string                           `json:"mode"`
	ReceiptActorPrincipalID *string                          `json:"receiptActorPrincipalId"`
	ExchangeFingerprint     string                           `json:"exchangeFingerprint"`
	ReceiptBinding          *EnrollmentCoownerReceiptBinding `json:"receiptBinding"`
	NativeHostID            string                           `json:"nativeHostId"`
}

type EnrollmentCoownerReceiptBinding struct {
	Pair               DomainPairConfirmation `json:"pair"`
	ResponseHash       string                 `json:"responseHash"`
	CurrentStateDigest *string                `json:"currentStateDigest"`
}

type domainCoownerContribution struct {
	State            string                 `json:"state"`
	GrantRevision    string                 `json:"grantRevision"`
	GrantCommandID   string                 `json:"grantCommandId"`
	GrantFingerprint string                 `json:"grantFingerprint"`
	ProfileRef       EnrollmentProfileRef   `json:"profileRef"`
	Grants           map[string]domainGrant `json:"grants"`
}

func isEnrollmentCoownerOperation(operation string) bool {
	return operation == EnrollmentCoownerGrant || operation == EnrollmentCoownerRevoke
}

func enrollmentCoownerRequest(r EnrollmentRequest) bool {
	return r.ContractRevision == EnrollmentCoownerRevision
}

func coownerSelfRevoke(actor EnrollmentVerified) bool {
	r := actor.Request
	return r.Operation == EnrollmentCoownerRevoke && r.TargetPrincipalID != nil && *r.TargetPrincipalID == actor.PrincipalID
}

func validateCoownerRequest(r EnrollmentRequest, maximum int) error {
	c := r.CoownerChange
	if !isEnrollmentCoownerOperation(r.Operation) || c == nil || r.Administration != nil || r.TargetPrincipalID == nil {
		return fmt.Errorf("closed human co-owner operation/change required")
	}
	if enrollmentIdentifiers(maximum, c.FounderPrincipalID, c.OwnershipRevision, *r.TargetPrincipalID) != nil || c.FounderPrincipalID == *r.TargetPrincipalID {
		return fmt.Errorf("co-owner target cannot be the original founder")
	}
	if domainWorkloadIdentity(*r.TargetPrincipalID, "") || domainWorkloadIdentity(c.FounderPrincipalID, "") || !validEnrollmentOwnedRevision(r.ExpectedRevision) {
		return fmt.Errorf("co-owner human target and owned CAS required")
	}
	for _, revision := range []*string{c.ExpectedTargetGrantRevision, c.ExpectedCoownerGrantRevision, c.OwnerGrantRevision} {
		if revision != nil && enrollmentIdentifiers(maximum, *revision) != nil {
			return fmt.Errorf("invalid co-owner revision")
		}
	}
	if r.Operation == EnrollmentCoownerRevoke {
		if c.ExpectedCoownerGrantRevision == nil || c.OwnerGrantRevision != nil || c.ExpectedTargetGrantRevision != nil && !domainEqual(c.ExpectedTargetGrantRevision, c.ExpectedCoownerGrantRevision) {
			return fmt.Errorf("revoke requires exact old generation and null new generation")
		}
		return nil
	}
	if c.ExpectedTargetGrantRevision == nil || c.OwnerGrantRevision == nil || domainEqual(c.ExpectedTargetGrantRevision, c.OwnerGrantRevision) || domainEqual(c.ExpectedCoownerGrantRevision, c.OwnerGrantRevision) {
		return fmt.Errorf("grant requires current member and a new reserved owner generation")
	}
	return nil
}

func coownerInspectionFingerprint(request EnrollmentRequest, principal string) string {
	raw, err := CanonicalDomainJSON(request)
	if err != nil {
		return ""
	}
	value := map[string]interface{}{"contractRevision": EnrollmentCoownerProofRevision, "mode": "inspect", "receiptActorPrincipalId": principal, "requestFingerprint": stagedHash(raw)}
	encoded, err := CanonicalDomainJSON(value)
	if err != nil {
		return ""
	}
	return stagedHash(encoded)
}

func coownerActorAuthorized(actor EnrollmentVerified) bool {
	a := actor.CoownerAuthority
	return actor.Kind == "human" && actor.OwnerAuthorized && !actor.AdministratorAuthorized && a != nil && !a.ReceiptAuthorized && actor.EnrollmentCoownerWire != nil && actor.Mode == "apply"
}

func coownerACLRevision(revision string) bool {
	return revision == domainACLRevision || revision == domainCoownerACLRevision
}

func coownerEligible(actor DomainVerified, contribution domainCoownerContribution) bool {
	return actor.Kind == "human" && contribution.State == "installed" && contribution.GrantRevision != "" && contribution.GrantRevision == actor.GrantRevision
}

// Each candidate authorizes the complete request. Partial rights never combine.
func domainGrantAllows(actor DomainVerified, grant domainGrant, access DomainAccess) bool {
	return authorizeDomainGrant(actor, grant, true, access) == nil
}

func coownerGrantAllows(actor DomainVerified, contribution domainCoownerContribution, access DomainAccess) bool {
	grant, present := contribution.Grants[access.Operation]
	return present && coownerEligible(actor, contribution) && grant.TargetGrantRevision == contribution.GrantRevision && domainGrantAllows(actor, grant, access)
}
