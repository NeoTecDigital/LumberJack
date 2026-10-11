// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"sync"
)

const DomainRevision = "manifest-domain-handoff/0.1"

type DomainBounds = stagedBounds
type DomainNativeBinding = stagedBinding
type DomainScope struct {
	AccountID string `json:"accountId"`
	Product   string `json:"product"`
}
type DomainBinding struct {
	Scope           DomainScope `json:"scope"`
	RootID          string      `json:"rootId"`
	BindingRevision string      `json:"bindingRevision"`
}
type DomainResource struct {
	AccountID   string  `json:"accountId"`
	Kind        string  `json:"kind"`
	ResourceID  string  `json:"resourceId"`
	ContextKind *string `json:"contextKind"`
}
type DomainFieldSet struct {
	Resource DomainResource `json:"resource"`
	Fields   []string       `json:"fields"`
}
type DomainIntent struct {
	ContractRevision   string           `json:"contractRevision"`
	Scope              DomainScope      `json:"scope"`
	Binding            DomainBinding    `json:"binding"`
	Mode               string           `json:"mode"`
	Operation          *string          `json:"operation"`
	Method             string           `json:"method"`
	Target             string           `json:"target"`
	RequestFingerprint string           `json:"requestFingerprint"`
	Resources          []DomainResource `json:"resources"`
	Fields             []DomainFieldSet `json:"fields"`
}
type DomainLease struct {
	Epoch             string        `json:"epoch"`
	LeaseID           string        `json:"leaseId"`
	PrincipalID       string        `json:"principalId"`
	SessionID         string        `json:"sessionId"`
	Scope             DomainScope   `json:"scope"`
	Binding           DomainBinding `json:"binding"`
	IntentFingerprint string        `json:"intentFingerprint"`
}
type DomainVerified struct {
	ContractRevision          string       `json:"contractRevision"`
	PrincipalID               string       `json:"principalId"`
	Kind                      string       `json:"kind"`
	SessionID                 string       `json:"sessionId"`
	Scope                     DomainScope  `json:"scope"`
	Intent                    DomainIntent `json:"intent"`
	GrantRevision             string       `json:"grantRevision"`
	AuthorityResourceRevision string       `json:"authorityResourceRevision"`
	ExpiresAt                 float64      `json:"expiresAt"`
	Issuer                    string       `json:"issuer"`
	Audience                  string       `json:"audience"`
	Phase                     string       `json:"phase"`
	LeaseBinding              *DomainLease `json:"leaseBinding"`
	ProofBinding              string       `json:"proofBinding"`
}
type DomainCheck struct {
	ContractRevision string       `json:"contractRevision"`
	Proof            string       `json:"proof"`
	Phase            string       `json:"phase"`
	Audience         string       `json:"audience"`
	Intent           DomainIntent `json:"intent"`
	LeaseBinding     *DomainLease `json:"leaseBinding"`
}
type DomainRoute struct {
	Method string `json:"method"`
	Target string `json:"target"`
}
type DomainLayout struct {
	Kinds    map[string]string              `json:"kinds"`
	Fields   map[string]string              `json:"fields"`
	Routes   map[string]DomainRoute         `json:"routes"`
	Profiles map[string]map[string][]string `json:"profiles"`
}
type DomainOwnedScope struct {
	Binding DomainNativeBinding `json:"binding"`
	Bounds  DomainBounds        `json:"bounds"`
	Layout  DomainLayout        `json:"layout"`
}
type DomainConfig struct {
	OwnerControlToken string             `json:"ownerControlToken"`
	Trust             ActivationConfig   `json:"trust"`
	HostID            string             `json:"hostId"`
	ControlToken      string             `json:"controlToken"`
	ACLMetadataKey    string             `json:"aclMetadataKey"`
	MaxLeases         int                `json:"maxLeases"`
	MaxRetainedEpochs int                `json:"maxRetainedEpochs"`
	MaxResources      int                `json:"maxResources"`
	MaxFields         int                `json:"maxFields"`
	MaxRequestBytes   int                `json:"maxRequestBytes"`
	MaxResponseBytes  int                `json:"maxResponseBytes"`
	Scopes            []DomainOwnedScope `json:"scopes"`
}
type DomainInput struct {
	Mode   string          `json:"mode"`
	Method string          `json:"method"`
	Target string          `json:"target"`
	Body   json.RawMessage `json:"body"`
}
type DomainRequest struct {
	DomainInput
	RequestID string `json:"requestId"`
	Proof     string `json:"proof"`
}
type DomainRecord = stagedRecord
type DomainDelta = stagedDelta
type DomainWrite = stagedWrite
type DomainCreate = stagedCreate
type DomainView struct {
	Binding        DomainNativeBinding
	Revision       string
	Records        map[string]DomainRecord
	AllocateID     func() (string, error)
	CreateACL      func(string) (interface{}, error)
	ACLMetadataKey string
}
type DomainCommand struct {
	CommandID        string
	ExpectedRevision string
	Operation        string
}
type DomainProduct interface {
	Resolve(DomainInput, DomainOwnedScope, DomainView) (DomainIntent, error)
	Command(DomainInput) (DomainCommand, error)
	Build(DomainInput, DomainOwnedScope, DomainView) (DomainDelta, error)
	Project(string, DomainIntent, DomainOwnedScope, DomainView) ([]byte, error)
	PublicFields(string, []string, DomainOwnedScope) ([]string, error)
}
type DomainAccess struct {
	Operation string
	Kind      string
	Fields    []string
	Create    bool
	Reference bool
}
type DomainPolicy interface {
	AuthorizeLocked(DomainVerified, DomainAccess, DomainRecord) error
	CreateACLLocked(DomainVerified, string, string, DomainRecord) (interface{}, error)
}
type DomainPairConfirmation struct {
	Epoch              string        `json:"epoch"`
	ScopeID            string        `json:"scopeId"`
	ReceiptKey         string        `json:"receiptKey"`
	NativeFingerprint  string        `json:"nativeFingerprint"`
	RequestFingerprint string        `json:"requestFingerprint"`
	ExpectedRevision   string        `json:"expectedRevision"`
	Revision           string        `json:"revision"`
	ReceiptHash        string        `json:"receiptHash"`
	Sequence           uint64        `json:"sequence"`
	SnapshotHash       string        `json:"snapshotHash"`
	CommandID          string        `json:"commandId"`
	PrincipalID        string        `json:"principalId"`
	Scope              DomainScope   `json:"scope"`
	Binding            DomainBinding `json:"binding"`
}
type DomainBegin struct {
	Lease        DomainLease `json:"lease"`
	ExchangeID   string      `json:"exchangeId"`
	ResponseHash string      `json:"responseHash"`
}
type DomainReceived struct {
	Body         []byte                  `json:"body"`
	ResponseHash string                  `json:"responseHash"`
	Lease        DomainLease             `json:"lease"`
	Pair         *DomainPairConfirmation `json:"pair"`
}
type DomainControl struct {
	Action       string          `json:"action"`
	Epoch        string          `json:"epoch"`
	LeaseID      string          `json:"leaseId"`
	HostID       string          `json:"hostId"`
	ChannelToken string          `json:"channelToken"`
	Proof        string          `json:"proof,omitempty"`
	PermitID     string          `json:"permitId,omitempty"`
	ResponseHash string          `json:"responseHash,omitempty"`
	Disposition  string          `json:"disposition,omitempty"`
	LeaseBinding *DomainLease    `json:"leaseBinding,omitempty"`
	Intent       *DomainIntent   `json:"intent,omitempty"`
	PrincipalID  string          `json:"principalId,omitempty"`
	SessionID    string          `json:"sessionId,omitempty"`
	ValidUntil   float64         `json:"validUntil,omitempty"`
	Keys         []DomainGateKey `json:"keys,omitempty"`
}
type DomainGateKey struct {
	PrincipalID string      `json:"principalId"`
	SessionID   string      `json:"sessionId"`
	Scope       DomainScope `json:"scope"`
}
type DomainPermit struct {
	Epoch        string `json:"epoch"`
	LeaseID      string `json:"leaseId"`
	PermitID     string `json:"permitId"`
	ResponseHash string `json:"responseHash"`
}
type domainEntry struct {
	executing    bool
	receiptKey   string
	lease        DomainLease
	intent       DomainIntent
	input        DomainInput
	actor        DomainVerified
	owned        DomainOwnedScope
	product      DomainProduct
	body         []byte
	responseHash string
	pair         *DomainPairConfirmation
	adopted      bool
	permitID     string
	disposition  string
	finished     bool
	pendingKey   string
}
type domainEngine struct {
	mu       sync.Mutex
	config   DomainConfig
	verifier *activationVerifier
	policy   DomainPolicy
	products map[string]DomainProduct
	epoch    string
	scopes   map[DomainScope]DomainOwnedScope
	entries  map[string]*domainEntry
	closed   map[DomainGateKey]bool
}
type DomainControlResult struct {
	Value     interface{}
	Completed bool
}

// Control never grants a data actor. Its channel authenticates only the configured host.
type DomainPort interface {
	DomainResolve(context.Context, DomainInput) (DomainIntent, error)
	DomainCall(context.Context, DomainRequest) (DomainBegin, error)
}

type DomainCompletion struct {
	LeaseID      string
	ResponseHash string
	Disposition  string
	PermitID     string
}
