// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package core

import "encoding/json"

// PersonalBindings is private native persistence, never Metadata or an Auth store.
// Canonical references are provenance; current core/source checks remain mandatory.
type PersonalBindingLedger struct {
	Revision string                             `json:"revision"`
	Bindings map[string]PersonalBindingRecord   `json:"bindings"`
	Consents map[string]PersonalConsentRecord   `json:"consents"`
	Receipts map[string]PersonalProvisionRecord `json:"receipts"`
	Mappings map[string]PersonalMappingRecord   `json:"mappings,omitempty"`
}

// Multiple explicitly controlled roots share ONE immutable human reservation.
// These records are provenance, never current principal/account/data authority.
type PersonalNativeBinding struct {
	PrincipalID string                 `json:"principalId"`
	Account     PersonalAccountRef     `json:"account"`
	OwnerRef    PersonalNativeOwnerRef `json:"ownerRef"`
}
type PersonalResolvedMapping struct {
	MappingID             string                `json:"mappingId"`
	MappingRevision       string                `json:"mappingRevision"`
	ReservationID         string                `json:"reservationId"`
	ReservationRevision   string                `json:"reservationRevision"`
	Issuer                string                `json:"issuer"`
	Subject               string                `json:"subject"`
	Binding               PersonalNativeBinding `json:"binding"`
	NativeAuthorityRef    string                `json:"nativeAuthorityRef"`
	SourcePolicyRevision  string                `json:"sourcePolicyRevision"`
	ResolvedMappingSHA256 string                `json:"resolvedMappingSha256"`
}
type PersonalMappedGrant struct {
	PrincipalID  string             `json:"principalId"`
	Scope        PersonalGrantScope `json:"scope"`
	Account      PersonalAccountRef `json:"account"`
	Capabilities []string           `json:"capabilities"`
	Revision     string             `json:"revision"`
	State        string             `json:"state"`
}
type PersonalGrantScope struct {
	AccountID string `json:"accountId"`
	Product   string `json:"product"`
}
type PersonalCanonicalState struct {
	PrincipalRegistered     bool                 `json:"principalRegistered"`
	AccountRegistryRevision *string              `json:"accountRegistryRevision"`
	PersonalGrant           *PersonalMappedGrant `json:"personalGrant"`
}
type PersonalMappingRecord struct {
	Mapping         PersonalResolvedMapping           `json:"mapping"`
	Canonical       PersonalCanonicalState            `json:"canonical"`
	ConsentRef      string                            `json:"consentRef"`
	ConsentRevision string                            `json:"consentRevision"`
	Binding         *PersonalBindingRecord            `json:"binding"`
	History         map[string]PersonalMappingHistory `json:"history"`
}
type PersonalMappingHistory struct {
	Operation    string          `json:"operation"`
	CommandID    string          `json:"commandId"`
	StableSHA256 string          `json:"stableSha256"`
	Expected     *string         `json:"expected"`
	Result       json.RawMessage `json:"result"`
	ReceiptKey   string          `json:"receiptKey"`
	Binding      json.RawMessage `json:"binding"`
}
type PersonalAccountRef struct {
	AccountID   string             `json:"accountId"`
	AccountType string             `json:"accountType"`
	SubjectRef  PersonalSubjectRef `json:"subjectRef"`
}
type PersonalSubjectRef struct {
	Kind      string `json:"kind"`
	SubjectID string `json:"subjectId"`
}
type PersonalNativeOwnerRef struct {
	RuntimeID string `json:"runtimeId"`
	RootID    string `json:"rootId"`
	OwnerID   string `json:"ownerId"`
}
type PersonalEnrollmentReference struct {
	CommandID  string                 `json:"commandId"`
	Revision   string                 `json:"revision"`
	Enrollment PersonalEnrollmentSpec `json:"enrollment"`
}
type PersonalEnrollmentSpec struct {
	Mode                string  `json:"mode"`
	ExistingIdentityRef *string `json:"existingIdentityRef"`
	ExpectedRevision    *string `json:"expectedRevision"`
}
type PersonalBindingRecord struct {
	PrincipalID             string                      `json:"principalId"`
	Account                 PersonalAccountRef          `json:"account"`
	OwnerRef                PersonalNativeOwnerRef      `json:"ownerRef"`
	BindingRevision         string                      `json:"bindingRevision"`
	AccountRegistryRevision string                      `json:"accountRegistryRevision"`
	Enrollment              PersonalEnrollmentReference `json:"enrollment"`
	AssociationID           *string                     `json:"associationId"`
	AssociationRevision     *string                     `json:"associationRevision"`
	ConsentRef              *string                     `json:"consentRef"`
	OwnerKind               string                      `json:"ownerKind"`
}
type PersonalConsentRecord struct {
	ConsentRef    string `json:"consentRef"`
	Revision      string `json:"revision"`
	NativeOwnerID string `json:"nativeOwnerId"`
	RootID        string `json:"rootId"`
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject"`
	MappingRef    string `json:"mappingRef"`
	State         string `json:"state"`
	CommandID     string `json:"commandId"`
	CommandSHA256 string `json:"commandSha256"`
}
type PersonalProvisionReceipt struct {
	ContractRevision string                 `json:"contractRevision"`
	CommandID        string                 `json:"commandId"`
	PrincipalID      string                 `json:"principalId"`
	Account          PersonalAccountRef     `json:"account"`
	OwnerRef         PersonalNativeOwnerRef `json:"ownerRef"`
	BindingRevision  string                 `json:"bindingRevision"`
	RegistryRevision string                 `json:"registryRevision"`
	EnrollmentSHA256 string                 `json:"enrollmentSha256"`
	CommandSHA256    string                 `json:"commandSha256"`
	Effect           string                 `json:"effect"`
}
type PersonalProvisionRecord struct {
	// Payload is canonical stable command, excludes ephemeral candidate/proof/lease.
	Payload json.RawMessage          `json:"payload"`
	Receipt PersonalProvisionReceipt `json:"receipt"`
}
