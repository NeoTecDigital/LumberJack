// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"errors"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

const stagedScopeKey = "lumberjack.staged.scope/v1"
const stagedReceiptPrefix = "lumberjack.staged.receipt/v1:"

var errStagedProtected = errors.New("owned namespace requires staged access")
var errStagedUnconfigured = errors.New("owned namespace is not configured and reconciled")
var errStagedPending = errors.New("owned namespace has an unconfirmed command")

// Bounds are supplied by the owning caller; zero never selects a policy default.
type stagedBounds struct {
	MaxNodes           int `json:"maxNodes"`
	MaxChanges         int `json:"maxChanges"`
	MaxReceipts        int `json:"maxReceipts"`
	MaxIdentifierBytes int `json:"maxIdentifierBytes"`
	MaxValueDepth      int `json:"maxValueDepth"`
	MaxScopeBytes      int `json:"maxScopeBytes"`
	MaxSnapshotBytes   int `json:"maxSnapshotBytes"`
}

type stagedBinding struct {
	ProductID       string `json:"productId,omitempty"`
	BindingRevision string `json:"bindingRevision,omitempty"`
	ScopeID         string `json:"scopeId"`
	AccountID       string `json:"accountId"`
	AccountRootID   string `json:"accountRootId"`
	RootID          string `json:"rootId"`
}

type stagedDescriptor struct {
	Binding stagedBinding `json:"binding"`
	Bounds  stagedBounds  `json:"bounds"`
}

type stagedScope struct {
	descriptor stagedDescriptor
	configured bool
	reconciled bool
	pending    *stagedPending
}

type stagedCommand struct {
	PrincipalID      string `json:"principalId"`
	AccountID        string `json:"accountId"`
	ScopeID          string `json:"scopeId"`
	CommandID        string `json:"commandId"`
	ExpectedRevision string `json:"expectedRevision"`
	Action           string `json:"action"`
	BodySHA256       string `json:"bodySha256"`
}

type stagedAccess struct {
	Binding     stagedBinding
	PrincipalID string
	Action      string
	NodeID      string
	Kind        string
	Fields      []string
}

// These callbacks are trusted engine-local hooks, never remote calls or public DTOs.
type stagedAuthorizer func(stagedAccess) error
type stagedBuilder func(stagedView) (stagedDelta, error)

type stagedRecord struct {
	ID       string
	Kind     string
	Name     string
	Metadata map[string]interface{}
}

type stagedView struct {
	Binding    stagedBinding
	Revision   string
	Records    map[string]stagedRecord
	AllocateID func() (string, error)
}

type stagedWrite struct {
	NodeID string
	Key    string
	Value  interface{}
}

type stagedCreate struct {
	ID       string
	ParentID string
	Kind     string
	Name     string
	Metadata map[string]interface{}
}

type stagedDelta struct {
	Writes  []stagedWrite
	Creates []stagedCreate
}

type stagedTarget struct {
	NodeID string   `json:"nodeId"`
	Kind   string   `json:"kind"`
	Fields []string `json:"fields"`
}

type stagedReceipt struct {
	Version       int            `json:"version"`
	Command       stagedCommand  `json:"command"`
	Fingerprint   string         `json:"fingerprint"`
	AfterRevision string         `json:"afterRevision"`
	Targets       []stagedTarget `json:"targets"`
}

type stagedPending struct {
	root    *core.Node
	nodes   map[string]*core.Node
	receipt stagedReceipt
	key     string
}

type stagedPair struct {
	ScopeID       string
	Key           string
	Fingerprint   string
	AfterRevision string
	ReceiptHash   string
}

type stagedDurableStamp struct {
	Sequence     uint64
	SnapshotHash string
	Path         string
	Pair         stagedPair
}

type stagedResult struct {
	Status    string
	CommandID string
	Revision  string
	Durable   *stagedDurableStamp
}

type stagedPreparation struct {
	pending  *stagedPending
	snapshot stateSnapshot
	pair     stagedPair
	replayed bool
}
