// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
)

const PersonalSourceRevision = "activation-native-personal-source/0.1"
const PersonalProvisionRevision = "activation-personal-provision/0.1"

type SourceAccount = core.PersonalAccountRef
type SourceOwnerRef = core.PersonalNativeOwnerRef
type SourceEnrollment = core.PersonalEnrollmentReference
type NativePersonalProvisionReceipt = core.PersonalProvisionReceipt

type PersonalSourceConfig struct {
	ContractRevision     string               `json:"contractRevision"`
	HostID               string               `json:"hostId"`
	SourceAuthorityRef   string               `json:"sourceAuthorityRef"`
	SourcePolicyRevision string               `json:"sourcePolicyRevision"`
	ControlToken         string               `json:"controlToken"`
	CoreCallback         SourceCoreCallback   `json:"coreCallback"`
	Bounds               PersonalSourceBounds `json:"bounds"`
	StagedBounds         stagedBounds         `json:"stagedBounds"`
}
type SourceCoreCallback struct {
	Audience     string `json:"audience"`
	Issuer       string `json:"issuer"`
	Endpoint     string `json:"endpoint"`
	ChannelToken string `json:"channelToken"`
}
type PersonalSourceBounds struct {
	MaxRequestBytes   int     `json:"maxRequestBytes"`
	MaxResponseBytes  int     `json:"maxResponseBytes"`
	MaxSources        int     `json:"maxSources"`
	MaxBindings       int     `json:"maxBindings"`
	MaxContexts       int     `json:"maxContexts"`
	MaxResources      int     `json:"maxResources"`
	MaxFields         int     `json:"maxFields"`
	MaxLeases         int     `json:"maxLeases"`
	MaxRetainedEpochs int     `json:"maxRetainedEpochs"`
	LeaseSeconds      float64 `json:"leaseSeconds"`
	RequestSeconds    float64 `json:"requestSeconds"`
}
type SourceEnvelope struct {
	ContractRevision string          `json:"contractRevision"`
	Action           string          `json:"action"`
	Epoch            string          `json:"epoch"`
	HostID           string          `json:"hostId"`
	ChannelToken     string          `json:"channelToken"`
	RequestID        string          `json:"requestId"`
	ValidUntil       float64         `json:"validUntil"`
	Payload          json.RawMessage `json:"payload"`
}
type SourceResponse struct {
	ContractRevision string      `json:"contractRevision"`
	Action           string      `json:"action"`
	Epoch            string      `json:"epoch"`
	HostID           string      `json:"hostId"`
	RequestID        string      `json:"requestId"`
	Result           interface{} `json:"result"`
}
type SourceSubjectEvidence struct {
	Issuer     string  `json:"issuer"`
	Subject    string  `json:"subject"`
	Audience   string  `json:"audience"`
	SessionID  string  `json:"sessionId"`
	Assurance  string  `json:"assurance"`
	RequestID  string  `json:"requestId"`
	CheckedAt  float64 `json:"checkedAt"`
	ValidUntil float64 `json:"validUntil"`
}
type SourceActor struct {
	PrincipalID string                `json:"principalId"`
	Kind        string                `json:"kind"`
	SessionID   string                `json:"sessionId"`
	Evidence    SourceSubjectEvidence `json:"evidence"`
}
type SourceScope struct {
	AccountID string `json:"accountId"`
	Product   string `json:"product"`
}
type SourcePersonalGrant struct {
	PrincipalID  string        `json:"principalId"`
	Scope        SourceScope   `json:"scope"`
	Account      SourceAccount `json:"account"`
	Capabilities []string      `json:"capabilities"`
	Revision     string        `json:"revision"`
	State        string        `json:"state"`
}
type SourceNativeBinding struct {
	PrincipalID string         `json:"principalId"`
	Account     SourceAccount  `json:"account"`
	OwnerRef    SourceOwnerRef `json:"ownerRef"`
}
type SourceAssociationRecord struct {
	AssociationID        string              `json:"associationId"`
	Issuer               string              `json:"issuer"`
	Subject              string              `json:"subject"`
	Binding              SourceNativeBinding `json:"binding"`
	Revision             string              `json:"revision"`
	State                string              `json:"state"`
	NativeAuthorityRef   string              `json:"nativeAuthorityRef"`
	SourceRevision       string              `json:"sourceRevision"`
	SourcePolicyRevision string              `json:"sourcePolicyRevision"`
	ConsentRef           string              `json:"consentRef"`
	ConsentRevision      string              `json:"consentRevision"`
}
type NativeAssociationEvidence struct {
	Binding              SourceNativeBinding `json:"binding"`
	NativeAuthorityRef   string              `json:"nativeAuthorityRef"`
	ActorIssuer          string              `json:"actorIssuer"`
	ActorSubject         string              `json:"actorSubject"`
	ActorSessionID       string              `json:"actorSessionId"`
	NativeActorOwnerID   string              `json:"nativeActorOwnerId"`
	RequestID            string              `json:"requestId"`
	Purpose              string              `json:"purpose"`
	NativeRevision       string              `json:"nativeRevision"`
	SourcePolicyRevision string              `json:"sourcePolicyRevision"`
	ConsentRef           string              `json:"consentRef"`
	ConsentRevision      string              `json:"consentRevision"`
	CheckedAt            float64             `json:"checkedAt"`
	ValidUntil           float64             `json:"validUntil"`
}
type SourceLeaseRef struct {
	Epoch                  string  `json:"epoch"`
	HostID                 string  `json:"hostId"`
	LeaseID                string  `json:"leaseId"`
	RequestID              string  `json:"requestId"`
	OwnerRootBindingSHA256 string  `json:"ownerRootBindingSha256"`
	PayloadSHA256          string  `json:"payloadSha256"`
	SourceRevision         string  `json:"sourceRevision"`
	ConsentRevision        *string `json:"consentRevision"`
	ValidUntil             float64 `json:"validUntil"`
}
type PersonalSourceIntent struct {
	ContractRevision string              `json:"contractRevision"`
	Scope            SourceScope         `json:"scope"`
	OwnerRef         SourceOwnerRef      `json:"ownerRef"`
	BindingRevision  string              `json:"bindingRevision"`
	Action           string              `json:"action"`
	Method           string              `json:"method"`
	Target           string              `json:"target"`
	BodySHA256       string              `json:"bodySha256"`
	RequestSHA256    string              `json:"requestSha256"`
	Resources        []SourceResourceRef `json:"resources"`
	Fields           []SourceFieldSet    `json:"fields"`
}
type SourceResourceRef struct {
	Kind       string `json:"kind"`
	ResourceID string `json:"resourceId"`
}
type SourceFieldSet struct {
	Resource SourceResourceRef `json:"resource"`
	Fields   []string          `json:"fields"`
}
type SourceOwnerBinding struct {
	PrincipalID             string           `json:"principalId"`
	SessionID               string           `json:"sessionId"`
	Account                 SourceAccount    `json:"account"`
	OwnerRef                SourceOwnerRef   `json:"ownerRef"`
	BindingRevision         string           `json:"bindingRevision"`
	AccountRegistryRevision string           `json:"accountRegistryRevision"`
	Enrollment              SourceEnrollment `json:"enrollment"`
	AssociationID           *string          `json:"associationId"`
	AssociationRevision     *string          `json:"associationRevision"`
	SourceAuthorityRef      string           `json:"sourceAuthorityRef"`
	SourceRevision          string           `json:"sourceRevision"`
	PolicyRevision          string           `json:"policyRevision"`
	RequestID               string           `json:"requestId"`
	IntentSHA256            string           `json:"intentSha256"`
	CheckedAt               float64          `json:"checkedAt"`
	ValidUntil              float64          `json:"validUntil"`
}
type SourceResourceDecision struct {
	PrincipalID        string              `json:"principalId"`
	SessionID          string              `json:"sessionId"`
	Scope              SourceScope         `json:"scope"`
	OwnerRef           SourceOwnerRef      `json:"ownerRef"`
	BindingRevision    string              `json:"bindingRevision"`
	Action             string              `json:"action"`
	Resources          []SourceResourceRef `json:"resources"`
	Fields             []SourceFieldSet    `json:"fields"`
	IntentSHA256       string              `json:"intentSha256"`
	RequestID          string              `json:"requestId"`
	SourceAuthorityRef string              `json:"sourceAuthorityRef"`
	ResourceRevision   string              `json:"resourceRevision"`
	PolicyRevision     string              `json:"policyRevision"`
	CheckedAt          float64             `json:"checkedAt"`
	ValidUntil         float64             `json:"validUntil"`
}
type PersonalProvisionPayload struct {
	CommandID               string           `json:"commandId"`
	PrincipalID             string           `json:"principalId"`
	Scope                   SourceScope      `json:"scope"`
	Account                 SourceAccount    `json:"account"`
	Enrollment              SourceEnrollment `json:"enrollment"`
	TargetRuntimeID         string           `json:"targetRuntimeId"`
	CandidateRootID         string           `json:"candidateRootId"`
	CandidateOwnerID        string           `json:"candidateOwnerId"`
	ExpectedBindingRevision *string          `json:"expectedBindingRevision"`
	SourcePolicyRevision    string           `json:"sourcePolicyRevision"`
	CandidateRef            string           `json:"candidateRef"`
}
type PersonalProvisionIntent struct {
	PersonalProvisionPayload
	ContractRevision string                        `json:"contractRevision"`
	Operation        string                        `json:"operation"`
	Request          SourceProvisionRequestBinding `json:"request"`
	RequestSHA256    string                        `json:"requestSha256"`
	CommandSHA256    string                        `json:"commandSha256"`
	EnrollmentSHA256 string                        `json:"enrollmentSha256"`
}
type SourceProvisionRequestBinding struct {
	ABI           string `json:"abi"`
	Action        string `json:"action"`
	PayloadSHA256 string `json:"payloadSha256"`
}
type NativeProvisionCandidate struct {
	RuntimeID          string                          `json:"runtimeId"`
	Epoch              string                          `json:"epoch"`
	CandidateRef       string                          `json:"candidateRef"`
	CommandID          string                          `json:"commandId"`
	PrincipalID        string                          `json:"principalId"`
	SessionID          string                          `json:"sessionId"`
	Account            SourceAccount                   `json:"account"`
	RootID             string                          `json:"rootId"`
	OwnerID            string                          `json:"ownerId"`
	RegistryRevision   string                          `json:"registryRevision"`
	CommandSHA256      string                          `json:"commandSha256"`
	EnrollmentSHA256   string                          `json:"enrollmentSha256"`
	SourceAuthorityRef string                          `json:"sourceAuthorityRef"`
	SourceRevision     string                          `json:"sourceRevision"`
	PolicyRevision     string                          `json:"policyRevision"`
	RequestID          string                          `json:"requestId"`
	RequestSHA256      string                          `json:"requestSha256"`
	IntentSHA256       string                          `json:"intentSha256"`
	Phase              string                          `json:"phase"`
	CheckedAt          float64                         `json:"checkedAt"`
	ValidUntil         float64                         `json:"validUntil"`
	State              string                          `json:"state"`
	Receipt            *NativePersonalProvisionReceipt `json:"receipt"`
}
type ProvisionLeaseRef struct {
	Epoch            string `json:"epoch"`
	LeaseID          string `json:"leaseId"`
	PrincipalID      string `json:"principalId"`
	SessionID        string `json:"sessionId"`
	AccountID        string `json:"accountId"`
	RuntimeID        string `json:"runtimeId"`
	CandidateRef     string `json:"candidateRef"`
	RootID           string `json:"rootId"`
	OwnerID          string `json:"ownerId"`
	CommandSHA256    string `json:"commandSha256"`
	RequestSHA256    string `json:"requestSha256"`
	SourceRevision   string `json:"sourceRevision"`
	RegistryRevision string `json:"registryRevision"`
	Phase            string `json:"phase"`
}

func personalStablePayload(i PersonalProvisionIntent) json.RawMessage {
	body := map[string]interface{}{"commandId": i.CommandID, "principalId": i.PrincipalID, "scope": i.Scope, "account": i.Account, "enrollment": i.Enrollment, "targetRuntimeId": i.TargetRuntimeID, "candidateRootId": i.CandidateRootID, "candidateOwnerId": i.CandidateOwnerID, "expectedBindingRevision": i.ExpectedBindingRevision, "sourcePolicyRevision": i.SourcePolicyRevision}
	raw, _ := CanonicalDomainJSON(body)
	return raw
}
func personalCommandDigest(i PersonalProvisionIntent) string {
	return sourceCommandKey(map[string]interface{}{"operation": "personal.scope.provision", "payload": personalStablePayload(i)})
}
func validatePersonalIntent(i PersonalProvisionIntent, c PersonalSourceConfig) error {
	if i.ContractRevision != PersonalProvisionRevision || i.Operation != "personal.scope.provision" || i.Scope.Product != "momentum" || i.Scope.AccountID != i.Account.AccountID || i.Account.AccountType != "personal" || i.Account.SubjectRef.Kind != "user" {
		return sourceDenied()
	}
	if i.Request.ABI != "ic_lj_personal_source_call" || i.Request.Action != "binding.provision" || !domainValidHash(i.Request.PayloadSHA256) || i.RequestSHA256 != sourceCommandKey(i.Request) || i.CommandSHA256 != personalCommandDigest(i) || i.EnrollmentSHA256 != sourceCommandKey(i.Enrollment) {
		return sourceDenied()
	}
	if i.Enrollment.Enrollment.Mode != "new" || i.Enrollment.Enrollment.ExistingIdentityRef != nil || i.Enrollment.Enrollment.ExpectedRevision != nil || i.SourcePolicyRevision != c.SourcePolicyRevision {
		return sourceDenied()
	}
	return validateStagedIdentifiers(c.StagedBounds, i.CommandID, i.PrincipalID, i.Account.AccountID, i.Account.SubjectRef.SubjectID, i.TargetRuntimeID, i.CandidateRef, i.CandidateRootID, i.CandidateOwnerID)
}
func personalIntentFromCommand(raw json.RawMessage, c PersonalSourceConfig) (PersonalProvisionIntent, error) {
	var payload PersonalProvisionPayload
	if sourceDecode(raw, &payload, c.Bounds) != nil {
		return PersonalProvisionIntent{}, sourceInvalid()
	}
	request := SourceProvisionRequestBinding{"ic_lj_personal_source_call", "binding.provision", stagedHash(raw)}
	intent := PersonalProvisionIntent{payload, PersonalProvisionRevision, "personal.scope.provision", request, sourceCommandKey(request), "", sourceCommandKey(payload.Enrollment)}
	intent.CommandSHA256 = personalCommandDigest(intent)
	if err := validatePersonalIntent(intent, c); err != nil {
		return PersonalProvisionIntent{}, err
	}
	return intent, nil
}
