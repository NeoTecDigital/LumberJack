// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "encoding/json"

const EnrollmentRevision = "manifest-account-enrollment/0.2"
const EnrollmentProofRevision = "manifest-native-enrollment/0.2"
const EnrollmentProfileRevision = "manifest-native-provisioning-profile/0.2"
const EnrollmentRecordRevision = "manifest-native-enrollment-record/0.2"
const EnrollmentAdminRevision = "manifest-account-enrollment/0.3"
const EnrollmentAdminProofRevision = "manifest-native-enrollment/0.3"
const EnrollmentAdminRecordRevision = "manifest-native-enrollment-record/0.3"
const EnrollmentProvision = "manifest.scope.provision"
const EnrollmentReadGrant = "manifest.scope.read.grant"
const EnrollmentReadRevoke = "manifest.scope.read.revoke"

// These are replacement contracts, not a recovery of missing historical NE1.
type EnrollmentProfileRef struct {
	ProfileID       string `json:"profileId"`
	ProfileRevision string `json:"profileRevision"`
	ProfileDigest   string `json:"profileDigest"`
}

type DomainProvisioningProfile struct {
	ContractRevision string                            `json:"contractRevision"`
	ProfileRef       EnrollmentProfileRef              `json:"profileRef"`
	Bounds           DomainBounds                      `json:"bounds"`
	Layout           DomainLayout                      `json:"layout"`
	AccountRootKind  string                            `json:"accountRootKind"`
	OwnerGrants      map[string]map[string]domainGrant `json:"ownerGrants"`
}

type EnrollmentRequest struct {
	ContractRevision  string                    `json:"contractRevision"`
	Scope             DomainScope               `json:"scope"`
	CommandID         string                    `json:"commandId"`
	ExpectedRevision  string                    `json:"expectedRevision"`
	Operation         string                    `json:"operation"`
	TargetPrincipalID *string                   `json:"targetPrincipalId"`
	ProfileRef        EnrollmentProfileRef      `json:"profileRef"`
	Administration    *EnrollmentAdministration `json:"administration,omitempty"`
}

type EnrollmentInput struct {
	ContractRevision string            `json:"contractRevision"`
	RequestID        string            `json:"requestId"`
	Proof            string            `json:"proof"`
	Request          EnrollmentRequest `json:"request"`
}

type EnrollmentCheck struct {
	ContractRevision   string            `json:"contractRevision"`
	Proof              string            `json:"proof"`
	Phase              string            `json:"phase"`
	Audience           string            `json:"audience"`
	RequestID          string            `json:"requestId"`
	Request            EnrollmentRequest `json:"request"`
	RequestFingerprint string            `json:"requestFingerprint"`
	LeaseBinding       *DomainLease      `json:"leaseBinding"`
}

type EnrollmentVerified struct {
	ContractRevision          string                    `json:"contractRevision"`
	PrincipalID               string                    `json:"principalId"`
	Kind                      string                    `json:"kind"`
	SessionID                 string                    `json:"sessionId"`
	Scope                     DomainScope               `json:"scope"`
	RequestID                 string                    `json:"requestId"`
	Request                   EnrollmentRequest         `json:"request"`
	RequestFingerprint        string                    `json:"requestFingerprint"`
	GrantRevision             string                    `json:"grantRevision"`
	AuthorityPolicyRevision   string                    `json:"authorityPolicyRevision"`
	AuthorityResourceRevision string                    `json:"authorityResourceRevision"`
	ExpiresAt                 float64                   `json:"expiresAt"`
	Issuer                    string                    `json:"issuer"`
	Audience                  string                    `json:"audience"`
	Phase                     string                    `json:"phase"`
	LeaseBinding              *DomainLease              `json:"leaseBinding"`
	ProofBinding              string                    `json:"proofBinding"`
	OwnerAuthorized           bool                      `json:"ownerAuthorized"`
	AdministratorAuthorized   bool                      `json:"administratorAuthorized,omitempty"`
	PrincipalReference        *DomainPrincipalReference `json:"principalReference"`
	Purpose                   string                    `json:"purpose"`
}

type enrollmentRecordValue struct {
	ContractRevision          string                    `json:"contractRevision"`
	Request                   EnrollmentRequest         `json:"request"`
	RequestID                 string                    `json:"requestId"`
	PrincipalID               string                    `json:"principalId"`
	SessionID                 string                    `json:"sessionId"`
	RequestFingerprint        string                    `json:"requestFingerprint"`
	GrantRevision             string                    `json:"grantRevision"`
	AuthorityPolicyRevision   string                    `json:"authorityPolicyRevision"`
	AuthorityResourceRevision string                    `json:"authorityResourceRevision"`
	PrincipalReference        *DomainPrincipalReference `json:"principalReference"`
	TargetGrantRevision       *string                   `json:"targetGrantRevision"`
}

type enrollmentEntry struct {
	input          EnrollmentInput
	actor          EnrollmentVerified
	privateRequest json.RawMessage
}

type enrollmentSessionKey struct{ PrincipalID, SessionID string }

type EnrollmentRootSnapshot struct {
	Generation uint64              `json:"generation"`
	Roots      []EnrollmentRootRef `json:"roots"`
}

type EnrollmentRootRef struct {
	Scope   DomainScope    `json:"scope"`
	Binding *DomainBinding `json:"binding"`
	Epoch   string         `json:"epoch"`
	HostID  string         `json:"hostId"`
	LeaseID string         `json:"leaseId,omitempty"`
	Pending bool           `json:"pending"`
}
