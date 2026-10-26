package replication

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/hashicorp/raft"
	"io"
	"os"
	"time"
)

type Node struct {
	raft    *raft.Raft
	fsm     *machine
	gate    AdmissionGate
	timeout time.Duration
	lock    *os.File
}

func Open(c Config) (*Node, error) {
	if c.NodeID == "" || c.Transport == nil || c.Directory == "" || c.Gate == nil || c.Timeout <= 0 {
		return nil, ErrInvalid
	}
	lock, e := lockDirectory(c.Directory)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			unlockDirectory(lock)
		}
	}()
	d, e := openDisk(c.Directory, c.StorageKey)
	if e != nil {
		return nil, e
	}
	snaps := &snapshotStore{d, c.Directory}
	existing, e := raft.HasExistingState(d, d, snaps)
	if e != nil {
		return nil, e
	}
	if c.Bootstrap && existing {
		return nil, errors.New("replication: refusing existing-state bootstrap")
	}
	cfg := raft.DefaultConfig()
	cfg.LocalID = c.NodeID
	cfg.LogOutput = io.Discard
	f := newMachine()
	r, e := raft.NewRaft(cfg, f, d, d, snaps, c.Transport)
	if e != nil {
		return nil, e
	}
	n := &Node{r, f, c.Gate, c.Timeout, lock}
	if e = bootstrap(r, c); e != nil {
		r.Shutdown()
		return nil, e
	}
	success = true
	return n, nil
}
func (n *Node) wait(ctx context.Context, f raft.Future) error {
	timer := time.NewTimer(n.timeout)
	defer timer.Stop()
	done := make(chan error, 1)
	go func() { done <- f.Error() }()
	select {
	case e := <-done:
		if e == raft.ErrNotLeader {
			return ErrNotLeader
		}
		if e != nil {
			return ErrUnknown
		}
		return nil
	case <-ctx.Done():
		return ErrUnknown
	case <-timer.C:
		return ErrUnknown
	}
}
func (n *Node) ordered(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if n.raft.State() != raft.Leader {
		return ErrNotLeader
	}
	return n.wait(ctx, n.raft.Barrier(n.timeout))
}
func (n *Node) submit(ctx context.Context, w wire) (Result, error) {
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if n.raft.State() != raft.Leader {
		return Result{}, ErrNotLeader
	}
	b, e := json.Marshal(w)
	if e != nil {
		return Result{}, ErrInvalid
	}
	f := n.raft.Apply(b, n.timeout)
	if e = n.wait(ctx, f); e != nil {
		return Result{}, e
	}
	r, ok := f.Response().(Result)
	if !ok {
		return Result{}, ErrUnknown
	}
	return r, nil
}
func (n *Node) Apply(ctx context.Context, c Command) (Result, error) {
	if !validCommand(c) {
		return Result{}, ErrInvalid
	}
	if e := n.ordered(ctx); e != nil {
		return Result{}, e
	}
	n.fsm.mu.RLock()
	v := n.fsm.state.Fences[actorKey{c.Scope.key(), c.PrincipalID, c.SessionID}]
	n.fsm.mu.RUnlock()
	if e := n.gate(ctx, c, v); e != nil {
		return Result{}, errors.New("replication: admission refused")
	}
	return n.submit(ctx, wire{Command: &c})
}
func validCommand(c Command) bool {
	return c.Scope.valid() && c.CommandID != "" && len(c.CommandID) <= 256 && c.RecordKey != "" && len(c.RecordKey) <= 1024 && c.Operation != "" && c.PrincipalID != "" && c.SessionID != "" && len(c.Payload) <= 4<<20 && json.Valid(c.Payload) && len(c.Admission) <= 64<<10
}
func (n *Node) Read(ctx context.Context, s Scope, key string) (Record, bool, error) {
	if !s.valid() || key == "" {
		return Record{}, false, ErrInvalid
	}
	if e := n.ordered(ctx); e != nil {
		return Record{}, false, e
	}
	n.fsm.mu.RLock()
	defer n.fsm.mu.RUnlock()
	r, ok := n.fsm.state.Records[recordKey{s.key(), key}]
	r.Payload = append(json.RawMessage(nil), r.Payload...)
	return r, ok, nil
}
func (n *Node) Receipt(ctx context.Context, s Scope, id string) (Result, bool, error) {
	if !s.valid() || id == "" {
		return Result{}, false, ErrInvalid
	}
	if e := n.ordered(ctx); e != nil {
		return Result{}, false, e
	}
	n.fsm.mu.RLock()
	defer n.fsm.mu.RUnlock()
	r, ok := n.fsm.state.Receipts[recordKey{s.key(), id}]
	return r.Result, ok, nil
}

// Fence is a trusted authority port, never a public unauthenticated operation.
func (n *Node) Fence(ctx context.Context, s Scope, p, session string, v uint64) error {
	if !s.valid() || p == "" || session == "" || v == 0 {
		return ErrInvalid
	}
	_, e := n.submit(ctx, wire{Fence: &fence{s, p, session, v}})
	return e
}
func (n *Node) Close() error { e := n.raft.Shutdown().Error(); unlockDirectory(n.lock); return e }

func bootstrap(r *raft.Raft, c Config) error {
	if !c.Bootstrap {
		return nil
	}
	if len(c.Voters) != 3 {
		return ErrInvalid
	}
	return r.BootstrapCluster(raft.Configuration{Servers: c.Voters}).Error()
}
