// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"net/http"
)

const NativeCanonicalRevision = "activation-native-canonical-mapping/0.1"
const CanonicalMappingRevision = "activation-canonical-mapping/0.1"
const NativeCanonicalSchemaSHA256 = "9b82311e19dd216f3a8efed38300a13daafceee34eb4c8a8e6a1a82b479539e8"

type NativeControlConfig struct {
	ContractRevision     string             `json:"contractRevision"`
	Epoch                string             `json:"epoch"`
	HostID               string             `json:"hostId"`
	SourceAuthorityRef   string             `json:"sourceAuthorityRef"`
	SourcePolicyRevision string             `json:"sourcePolicyRevision"`
	JWT                  nativeControlJWT   `json:"jwt"`
	Seal                 nativeSealConfig   `json:"seal"`
	MappingCallback      SourceCoreCallback `json:"mappingCallback"`
}
type nativeControlJWT struct {
	SessionKey       []byte  `json:"sessionKey"`
	RefreshKey       []byte  `json:"refreshKey"`
	SecretKey        []byte  `json:"secretKey"`
	ExpiresInSeconds float64 `json:"expiresInSeconds"`
}
type nativeSealConfig struct {
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"keyId"`
	PrivateKey []byte `json:"privateKey"`
}
type nativeControlRuntime struct {
	config     NativeControlConfig
	client     *http.Client
	privateKey []byte
	publicKey  []byte
}
type CanonicalResolvedMapping = core.PersonalResolvedMapping
type CanonicalState = core.PersonalCanonicalState

type MappingCheckKey struct {
	CommandID           string  `json:"commandId"`
	RequestID           string  `json:"requestId"`
	RawRequestSHA256    string  `json:"rawRequestSha256"`
	StableCommandSHA256 string  `json:"stableCommandSha256"`
	ExpectedRevision    *string `json:"expectedRevision"`
	Phase               string  `json:"phase"`
}
type NativeControlSource struct {
	NativeAuthorityRef   string `json:"nativeAuthorityRef"`
	RuntimeID            string `json:"runtimeId"`
	HostID               string `json:"hostId"`
	Epoch                string `json:"epoch"`
	SourceRevision       string `json:"sourceRevision"`
	SourcePolicyRevision string `json:"sourcePolicyRevision"`
}
type NativeControlKey struct {
	ControlRef            string `json:"controlRef"`
	NativeSessionRef      string `json:"nativeSessionRef"`
	NativeProfileRef      string `json:"nativeProfileRef"`
	NativeCredentialEpoch string `json:"nativeCredentialEpoch"`
}
type ExistingRootKey struct {
	RootID          string `json:"rootId"`
	OwnerID         string `json:"ownerId"`
	CreatedBy       string `json:"createdBy"`
	RootRevision    string `json:"rootRevision"`
	LineageRevision string `json:"lineageRevision"`
}
type NativeControlSnapshot struct {
	Source     NativeControlSource   `json:"source"`
	Control    NativeControlKey      `json:"control"`
	Root       ExistingRootKey       `json:"root"`
	Subject    SourceSubjectEvidence `json:"subject"`
	RequestID  string                `json:"requestId"`
	Purpose    string                `json:"purpose"`
	CheckKey   MappingCheckKey       `json:"checkKey"`
	CheckedAt  float64               `json:"checkedAt"`
	ValidUntil float64               `json:"validUntil"`
	SealRef    string                `json:"sealRef"`
}
type ControlLeaseRef struct {
	Epoch                 string  `json:"epoch"`
	HostID                string  `json:"hostId"`
	LeaseID               string  `json:"leaseId"`
	RequestID             string  `json:"requestId"`
	ControlRef            string  `json:"controlRef"`
	ControlSnapshotSHA256 string  `json:"controlSnapshotSha256"`
	SourceRevision        string  `json:"sourceRevision"`
	ValidUntil            float64 `json:"validUntil"`
}
type CurrentNativeConsent struct {
	Evidence NativeAssociationEvidence `json:"evidence"`
	CheckKey MappingCheckKey           `json:"checkKey"`
	SealRef  string                    `json:"sealRef"`
}
type PrecanonicalAssociationEvidence struct {
	ControlSnapshot NativeControlSnapshot     `json:"controlSnapshot"`
	Evidence        NativeAssociationEvidence `json:"evidence"`
	CheckKey        MappingCheckKey           `json:"checkKey"`
	SealRef         string                    `json:"sealRef"`
}
type mappingGuardRef struct {
	GuardRef            string  `json:"guardRef"`
	HostID              string  `json:"hostId"`
	Epoch               string  `json:"epoch"`
	RequestID           string  `json:"requestId"`
	CommandID           string  `json:"commandId"`
	RawRequestSHA256    string  `json:"rawRequestSha256"`
	StableCommandSHA256 string  `json:"stableCommandSha256"`
	ValidUntil          float64 `json:"validUntil"`
}
type verifiedCanonicalMapping struct {
	Stage               string                   `json:"stage"`
	Mapping             CanonicalResolvedMapping `json:"mapping"`
	Canonical           CanonicalState           `json:"canonical"`
	Subject             SourceSubjectEvidence    `json:"subject"`
	RequestID           string                   `json:"requestId"`
	Purpose             string                   `json:"purpose"`
	RawRequestSHA256    string                   `json:"rawRequestSha256"`
	StableCommandSHA256 string                   `json:"stableCommandSha256"`
	CheckedAt           float64                  `json:"checkedAt"`
	ValidUntil          float64                  `json:"validUntil"`
	ContractRevision    string                   `json:"contractRevision"`
}
type mappingGuard struct {
	Reference mappingGuardRef          `json:"reference"`
	Mapping   verifiedCanonicalMapping `json:"mapping"`
}
type mappingReleaseAck struct {
	GuardRef    string                    `json:"guardRef"`
	State       string                    `json:"state"`
	Transaction string                    `json:"transaction"`
	Current     *verifiedCanonicalMapping `json:"current"`
	CheckedAt   float64                   `json:"checkedAt"`
	ValidUntil  *float64                  `json:"validUntil"`
}
type mappingCallbackEnvelope struct {
	ContractRevision string          `json:"contractRevision"`
	Issuer           string          `json:"issuer"`
	Audience         string          `json:"audience"`
	HostID           string          `json:"hostId"`
	Epoch            string          `json:"epoch"`
	RequestID        string          `json:"requestId"`
	Action           string          `json:"action"`
	Payload          json.RawMessage `json:"payload"`
}
type mappingCallbackResponse struct {
	ContractRevision string          `json:"contractRevision"`
	Issuer           string          `json:"issuer"`
	Audience         string          `json:"audience"`
	HostID           string          `json:"hostId"`
	Epoch            string          `json:"epoch"`
	RequestID        string          `json:"requestId"`
	Action           string          `json:"action"`
	Result           json.RawMessage `json:"result"`
}

// Stored in the SAME p.entries. Control refs never impersonate SourceLease9.
type canonicalSourceEntry struct {
	control        ControlLeaseRef
	held           sourceControlEntry
	facts          nativeControlFacts
	subject        SourceSubjectEvidence
	key            MappingCheckKey
	originalSHA    string
	originalAction string
	source         *personalSourceEntry
	mapping        CanonicalResolvedMapping
	snapshot       NativeControlSnapshot
	association    *SourceAssociationRecord
	enrollment     *SourceEnrollment
	read           *sourceReadPermit
	write          *sourceWritePermit
	guard          *mappingGuardRef
	authorityUntil float64
	cleanupKnown   bool
	closing        bool
	unknown        bool
	seals          map[string]string
	ledger         *core.PersonalBindingLedger
	scope          *stagedScope
	pending        *stagedPending
	prepared       stateSnapshot
	durable        *stagedDurableStamp
	result         json.RawMessage
}
type nativeControlFacts struct {
	rootID       string
	sessionRef   string
	session      core.ApplicationSession
	profileEpoch int64
}
type nativeControlCapture struct {
	NativeControlCredential string  `json:"nativeControlCredential"`
	RootID                  *string `json:"rootId"`
}
type nativeControlOpen struct {
	ControlRef       string                `json:"controlRef"`
	Subject          SourceSubjectEvidence `json:"subject"`
	Purpose          string                `json:"purpose"`
	CommandID        string                `json:"commandId"`
	ExpectedRevision *string               `json:"expectedRevision"`
	RawRequestSHA256 string                `json:"rawRequestSha256"`
}
type nativeControlRecheck struct {
	LeaseRef ControlLeaseRef       `json:"leaseRef"`
	Subject  SourceSubjectEvidence `json:"subject"`
	Purpose  string                `json:"purpose"`
	CheckKey MappingCheckKey       `json:"checkKey"`
}
type nativeControlRelease struct {
	LeaseRef    ControlLeaseRef `json:"leaseRef"`
	Disposition string          `json:"disposition"`
}
type canonicalConsentInput struct {
	CommandID               string                   `json:"commandId"`
	ControlRef              string                   `json:"controlRef"`
	SupabaseEvidence        SourceSubjectEvidence    `json:"supabaseEvidence"`
	CanonicalMappingRef     string                   `json:"canonicalMappingRef"`
	RootID                  string                   `json:"rootId"`
	OwnerID                 string                   `json:"ownerId"`
	ExpectedConsentRevision *string                  `json:"expectedConsentRevision"`
	ResolvedMapping         CanonicalResolvedMapping `json:"resolvedMapping"`
}
type canonicalAttachInput struct {
	CanonicalMappingRef     string                  `json:"canonicalMappingRef"`
	Subject                 SourceSubjectEvidence   `json:"subject"`
	Record                  SourceAssociationRecord `json:"record"`
	EnrollmentRef           SourceEnrollment        `json:"enrollmentRef"`
	CommandID               string                  `json:"commandId"`
	ExpectedBindingRevision *string                 `json:"expectedBindingRevision"`
}
type canonicalAttachResult struct {
	CommandID       string `json:"commandId"`
	MappingID       string `json:"mappingId"`
	BindingRevision string `json:"bindingRevision"`
	Effect          string `json:"effect"`
}
type precanonicalIdentityOpen struct {
	NativeEvidenceRef string                   `json:"nativeEvidenceRef"`
	Subject           SourceSubjectEvidence    `json:"subject"`
	Purpose           string                   `json:"purpose"`
	Record            *SourceAssociationRecord `json:"record"`
}
type currentSealLease struct {
	Kind      string          `json:"kind"`
	Reference json.RawMessage `json:"reference"`
}
type mappingCurrentSeal struct {
	LeaseRef      currentSealLease      `json:"leaseRef"`
	Subject       SourceSubjectEvidence `json:"subject"`
	Purpose       string                `json:"purpose"`
	CheckKey      MappingCheckKey       `json:"checkKey"`
	AssociationID string                `json:"associationId"`
	EnrollmentRef SourceEnrollment      `json:"enrollmentRef"`
}

type nativeSourceIdentity struct {
	NativeAuthorityRef   string `json:"nativeAuthorityRef"`
	RuntimeID            string `json:"runtimeId"`
	HostID               string `json:"hostId"`
	Epoch                string `json:"epoch"`
	SourcePolicyRevision string `json:"sourcePolicyRevision"`
}
type nativeVerifyPolicy struct {
	ContractRevision string               `json:"contractRevision"`
	SourceIdentity   nativeSourceIdentity `json:"sourceIdentity"`
	KeyID            string               `json:"keyId"`
	PublicKey        []byte               `json:"publicKey"`
	Bounds           PersonalSourceBounds `json:"bounds"`
}
type nativeVerifyExpected struct {
	Kind          string                `json:"kind"`
	Subject       SourceSubjectEvidence `json:"subject"`
	RequestID     string                `json:"requestId"`
	Purpose       string                `json:"purpose"`
	CheckKey      MappingCheckKey       `json:"checkKey"`
	AssociationID *string               `json:"associationId"`
	EnrollmentRef *SourceEnrollment     `json:"enrollmentRef"`
	Now           float64               `json:"now"`
}
type nativeVerifyInput struct {
	Policy   nativeVerifyPolicy   `json:"policy"`
	Snapshot json.RawMessage      `json:"snapshot"`
	Expected nativeVerifyExpected `json:"expected"`
}
type nativeSignedSeal struct {
	ContractRevision string               `json:"contractRevision"`
	KeyID            string               `json:"keyId"`
	SealID           string               `json:"sealId"`
	PermitKind       string               `json:"permitKind"`
	SourceIdentity   nativeSourceIdentity `json:"sourceIdentity"`
	Snapshot         json.RawMessage      `json:"snapshot"`
	AssociationID    *string              `json:"associationId"`
	EnrollmentRef    *SourceEnrollment    `json:"enrollmentRef"`
}
