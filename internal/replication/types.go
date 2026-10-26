// Package replication provides injected, encrypted Raft persistence.
package replication

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/hashicorp/raft"
	"time"
)

var (
	ErrUnknown   = errors.New("replication: unknown outcome; resolve by receipt")
	ErrNotLeader = errors.New("replication: leader required")
	ErrInvalid   = errors.New("replication: invalid command")
)

type Scope struct {
	AccountID   string `json:"accountId"`
	Product     string `json:"product"`
	WorkspaceID string `json:"workspaceId,omitempty"`
}
type Command struct {
	Scope            Scope           `json:"scope"`
	CommandID        string          `json:"commandId"`
	Operation        string          `json:"operation"`
	RecordKey        string          `json:"recordKey"`
	ExpectedRevision uint64          `json:"expectedRevision"`
	Payload          json.RawMessage `json:"payload"`
	PrincipalID      string          `json:"principalId"`
	SessionID        string          `json:"sessionId"`
	BarrierVersion   uint64          `json:"barrierVersion"`
	Admission        json.RawMessage `json:"admission,omitempty"`
}
type Record struct {
	Revision uint64          `json:"revision"`
	Payload  json.RawMessage `json:"payload"`
}
type Result struct {
	Revision  uint64 `json:"revision"`
	CommandID string `json:"commandId"`
	Replay    bool   `json:"replay"`
	Outcome   string `json:"outcome"`
}

// AdmissionGate must validate exact actor, scope, operation and payload binding.
// It runs on the leader before submission; only deterministic fences run in FSM.
type AdmissionGate func(context.Context, Command, uint64) error
type Config struct {
	NodeID     raft.ServerID
	Transport  raft.Transport
	Voters     []raft.Server
	Bootstrap  bool
	Directory  string
	StorageKey []byte
	Timeout    time.Duration
	Gate       AdmissionGate
}
type scopeKey struct{ Account, Product, Workspace string }

func (s Scope) key() scopeKey { return scopeKey{s.AccountID, s.Product, s.WorkspaceID} }
func (s Scope) valid() bool {
	return s.AccountID != "" && (s.Product == "momentum" || s.Product == "manifest")
}

type actorKey struct {
	Scope              scopeKey
	Principal, Session string
}
type recordKey struct {
	Scope scopeKey
	Key   string
}
type wire struct {
	Command *Command `json:"command,omitempty"`
	Fence   *fence   `json:"fence,omitempty"`
}
type fence struct {
	Scope              Scope
	Principal, Session string
	Version            uint64
}
