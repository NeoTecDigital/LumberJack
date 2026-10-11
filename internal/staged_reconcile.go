// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/sha256"
	"fmt"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func (s *Server) stageOwnedCommand(command stagedCommand, authorize stagedAuthorizer, build stagedBuilder) (stagedResult, error) {
	prepared, err := s.prepareOwnedCommand(command, authorize, build)
	if err != nil {
		return stagedResult{Status: stagedFailureStatus(err), CommandID: command.CommandID}, err
	}
	stamp, err := s.stateWriter.commitPaired(prepared.snapshot, prepared.pair)
	if err != nil {
		return stagedResult{Status: "unknown", CommandID: command.CommandID}, err
	}
	if err := s.publishOwnedPair(command.ScopeID, prepared.pending, stamp); err != nil {
		return stagedResult{Status: "unknown", CommandID: command.CommandID}, err
	}
	status := "applied"
	if prepared.replayed {
		status = "replayed"
	}
	return stagedResult{Status: status, CommandID: command.CommandID,
		Revision: prepared.pair.AfterRevision, Durable: &stamp}, nil
}

func stagedFailureStatus(err error) string {
	if carried, ok := err.(*apiError); ok && carried.status == 409 {
		return "conflict"
	}
	// Authority/unavailability must not relabel an earlier same-key unknown as refused.
	return "unknown"
}

func (s *Server) prepareOwnedCommand(command stagedCommand, authorize stagedAuthorizer, build stagedBuilder) (stagedPreparation, error) {
	s.forestMutex.Lock()
	defer s.forestMutex.Unlock()
	scope := s.stagedScopes[command.ScopeID]
	if scope == nil || !scope.configured || !scope.reconciled || authorize == nil || build == nil {
		return stagedPreparation{}, errStagedUnconfigured
	}
	if err := validateStagedCommand(scope, command); err != nil {
		return stagedPreparation{}, err
	}
	if err := authorize(stagedAccess{Binding: scope.descriptor.Binding, PrincipalID: command.PrincipalID, Action: command.Action}); err != nil {
		return stagedPreparation{}, err
	}
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return stagedPreparation{}, err
	}
	root := index[scope.descriptor.Binding.RootID]
	if root == nil {
		return stagedPreparation{}, fmt.Errorf("owned root is missing")
	}
	key := stagedCommandKey(command)
	if scope.pending != nil {
		return s.preparePendingReplayLocked(scope, command, authorize, key)
	}
	if previous, present := root.CommandReceipts[key]; present {
		return s.prepareReceiptReplayLocked(scope, command, authorize, key, previous)
	}
	for id, node := range s.stagedOverlayLocked() {
		index[id] = node
	}
	return s.prepareNewOwnedCommandLocked(scope, root, index, command, authorize, build)
}

func (s *Server) preparePendingReplayLocked(scope *stagedScope, command stagedCommand, authorize stagedAuthorizer, key string) (stagedPreparation, error) {
	pending := scope.pending
	if pending.key != key {
		return stagedPreparation{}, errStagedPending
	}
	if pending.receipt.Fingerprint != stagedCommandFingerprint(scope.descriptor.Binding, command) {
		return stagedPreparation{}, apiErrorf(409, "command_conflict")
	}
	if err := authorizeStagedReplay(authorize, scope.descriptor.Binding, pending.receipt); err != nil {
		return stagedPreparation{}, err
	}
	return s.snapshotOwnedPreparationLocked(scope, pending, key, true)
}

func (s *Server) prepareReceiptReplayLocked(scope *stagedScope, command stagedCommand, authorize stagedAuthorizer, key string, previous interface{}) (stagedPreparation, error) {
	var receipt stagedReceipt
	if err := decodeStagedInternal(previous, &receipt); err != nil {
		return stagedPreparation{}, err
	}
	if receipt.Fingerprint != stagedCommandFingerprint(scope.descriptor.Binding, command) {
		return stagedPreparation{}, apiErrorf(409, "command_conflict")
	}
	if err := authorizeStagedReplay(authorize, scope.descriptor.Binding, receipt); err != nil {
		return stagedPreparation{}, err
	}
	return s.snapshotOwnedPreparationLocked(scope, nil, key, true)
}

func (s *Server) prepareNewOwnedCommandLocked(scope *stagedScope, root *core.Node, index map[string]*core.Node, command stagedCommand, authorize stagedAuthorizer, build stagedBuilder) (stagedPreparation, error) {
	if len(root.CommandReceipts)-1 >= scope.descriptor.Bounds.MaxReceipts {
		return stagedPreparation{}, fmt.Errorf("owned receipt capacity reached; keys are never silently evicted")
	}
	revision, err := stagedContentRevision(root)
	if err != nil {
		return stagedPreparation{}, err
	}
	if command.ExpectedRevision != revision {
		return stagedPreparation{}, apiErrorf(409, "revision_conflict")
	}
	pending, err := buildOwnedPending(scope, root, index, command, authorize, build)
	if err != nil {
		return stagedPreparation{}, err
	}
	scope.pending = pending
	prepared, err := s.snapshotOwnedPreparationLocked(scope, pending, pending.key, false)
	if err != nil {
		scope.pending = nil // No snapshot escaped; this candidate was never admitted to persistence.
	}
	return prepared, err
}

func buildOwnedPending(scope *stagedScope, root *core.Node, occupied map[string]*core.Node, command stagedCommand, authorize stagedAuthorizer, build stagedBuilder) (*stagedPending, error) {
	nodes, err := stagedClosure(root, scope.descriptor.Bounds)
	if err != nil {
		return nil, err
	}
	nodes, err = cloneStagedNodes(nodes, scope.descriptor.Bounds)
	if err != nil {
		return nil, err
	}
	allocated := map[string]bool{}
	view, err := newStagedView(scope, nodes, command.ExpectedRevision, allocated)
	if err != nil {
		return nil, err
	}
	delta, err := build(view)
	if err != nil {
		return nil, err
	}
	targets, err := applyStagedDelta(scope, nodes, delta, allocated, command, authorize, occupied)
	if err != nil {
		return nil, err
	}
	candidate := nodes[root.ID]
	revision, err := validateOwnedCandidate(candidate, scope.descriptor.Bounds)
	if err != nil {
		return nil, err
	}
	receipt := stagedReceipt{Version: 1, Command: command,
		Fingerprint: stagedCommandFingerprint(scope.descriptor.Binding, command), AfterRevision: revision, Targets: targets}
	key := stagedCommandKey(command)
	candidate.CommandReceipts[key] = receipt
	if _, err := validateOwnedCandidate(candidate, scope.descriptor.Bounds); err != nil {
		return nil, err
	}
	return &stagedPending{root: candidate, nodes: nodes, receipt: receipt, key: key}, nil
}

func validateOwnedCandidate(root *core.Node, bounds stagedBounds) (string, error) {
	data, err := encodeState(root)
	if err != nil {
		return "", err
	}
	if len(data) > bounds.MaxScopeBytes {
		return "", fmt.Errorf("owned candidate exceeds scope byte bound")
	}
	return stagedContentRevision(root)
}

func (s *Server) snapshotOwnedPreparationLocked(scope *stagedScope, pending *stagedPending, key string, replayed bool) (stagedPreparation, error) {
	snapshot, err := s.encodeSnapshotLocked(s.statePath(), false)
	if err != nil {
		return stagedPreparation{}, err
	}
	pair, present := snapshot.pairs[stagedPairKey(scope.descriptor.Binding.ScopeID, key)]
	if !present {
		return stagedPreparation{}, fmt.Errorf("composed snapshot does not contain its required receipt")
	}
	return stagedPreparation{pending: pending, snapshot: snapshot, pair: pair, replayed: replayed}, nil
}

func (s *Server) publishOwnedPair(scopeID string, pending *stagedPending, stamp stagedDurableStamp) error {
	s.forestMutex.Lock()
	defer s.forestMutex.Unlock()
	scope := s.stagedScopes[scopeID]
	if scope == nil || stamp.Pair.ScopeID != scopeID || stamp.Sequence == 0 || stamp.SnapshotHash == "" {
		return fmt.Errorf("missing actual paired durability stamp")
	}
	if pending == nil || scope.pending == nil {
		return nil
	}
	if scope.pending != pending || pending.key != stamp.Pair.Key || pending.receipt.Fingerprint != stamp.Pair.Fingerprint {
		return fmt.Errorf("paired publication does not match the pending candidate")
	}
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return err
	}
	parent := index[scope.descriptor.Binding.AccountRootID]
	if parent == nil || parent.Children[scope.descriptor.Binding.RootID] == nil {
		return fmt.Errorf("owned account binding changed before publication")
	}
	parent.Children[scope.descriptor.Binding.RootID] = pending.root
	scope.pending = nil
	scope.reconciled = true
	live, err := encodeState(s.forest)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(live)
	s.lastHash = append([]byte(nil), hash[:]...)
	return nil
}

func (s *Server) readOwnedScope(scopeID string, authorize stagedAuthorizer) (stagedView, error) {
	s.forestMutex.RLock()
	defer s.forestMutex.RUnlock()
	scope := s.stagedScopes[scopeID]
	if scope == nil || !scope.configured || !scope.reconciled || authorize == nil {
		return stagedView{}, errStagedUnconfigured
	}
	if scope.pending != nil {
		return stagedView{}, errStagedPending
	}
	if err := authorize(stagedAccess{Binding: scope.descriptor.Binding, Action: "scope.read"}); err != nil {
		return stagedView{}, err
	}
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return stagedView{}, err
	}
	root := index[scope.descriptor.Binding.RootID]
	nodes, err := stagedClosure(root, scope.descriptor.Bounds)
	if err != nil {
		return stagedView{}, err
	}
	revision, err := stagedContentRevision(root)
	if err != nil {
		return stagedView{}, err
	}
	view, err := newStagedView(scope, nodes, revision, map[string]bool{})
	view.AllocateID = nil
	return view, err
}

func (s *Server) reconcileOwnedCommand(scopeID, key string) (stagedResult, error) {
	s.forestMutex.Lock()
	scope := s.stagedScopes[scopeID]
	if scope == nil {
		s.forestMutex.Unlock()
		return stagedResult{Status: "unknown"}, errStagedUnconfigured
	}
	if scope.pending != nil && scope.pending.key != key {
		s.forestMutex.Unlock()
		return stagedResult{Status: "unknown"}, errStagedPending
	}
	prepared, err := s.snapshotOwnedPreparationLocked(scope, scope.pending, key, true)
	s.forestMutex.Unlock()
	if err != nil {
		return stagedResult{Status: "unknown"}, err
	}
	stamp, err := s.stateWriter.commitPaired(prepared.snapshot, prepared.pair)
	if err != nil {
		return stagedResult{Status: "unknown"}, err
	}
	if err := s.publishOwnedPair(scopeID, prepared.pending, stamp); err != nil {
		return stagedResult{Status: "unknown"}, err
	}
	return stagedResult{Status: "replayed", Revision: prepared.pair.AfterRevision, Durable: &stamp}, nil
}

func (s *Server) restoreStagedScopes(path string) error {
	s.forestMutex.Lock()
	index, err := stagedForestIndex(s.forest)
	if err == nil {
		err = s.restoreStagedDescriptorsLocked(index)
	}
	if err != nil || len(s.stagedScopes) == 0 {
		s.forestMutex.Unlock()
		return err
	}
	snapshot, err := s.encodeSnapshotLocked(path, false)
	snapshot.force = true
	s.forestMutex.Unlock()
	if err != nil {
		return err
	}
	if err := s.commitState(snapshot); err != nil {
		return err
	}
	s.forestMutex.Lock()
	for _, scope := range s.stagedScopes {
		scope.reconciled = true
	}
	s.forestMutex.Unlock()
	return nil
}

func (s *Server) restoreStagedDescriptorsLocked(index map[string]*core.Node) error {
	s.stagedScopes = map[string]*stagedScope{}
	descriptors := map[string]stagedDescriptor{}
	for _, node := range index {
		if !isStagedNode(node) {
			continue
		}
		var descriptor stagedDescriptor
		if err := decodeStagedInternal(node.CommandReceipts[stagedScopeKey], &descriptor); err != nil {
			return err
		}
		if previous, present := descriptors[descriptor.Binding.ScopeID]; present && previous != descriptor {
			return fmt.Errorf("loaded scope has conflicting ownership descriptors")
		}
		descriptors[descriptor.Binding.ScopeID] = descriptor
	}
	closures := map[string]map[string]*core.Node{}
	for id, descriptor := range descriptors {
		if _, err := s.prepareStagedScopeLocked(descriptor); err != nil {
			return err
		}
		closure, err := stagedClosure(index[descriptor.Binding.RootID], descriptor.Bounds)
		if err != nil {
			return err
		}
		closures[id] = closure
	}
	if err := validateLoadedStagedMarkers(index, closures); err != nil {
		return err
	}
	return s.validateStagedScopesLocked()
}

func validateLoadedStagedMarkers(index map[string]*core.Node, closures map[string]map[string]*core.Node) error {
	for _, node := range index {
		if !isStagedNode(node) {
			continue
		}
		var descriptor stagedDescriptor
		if decodeStagedInternal(node.CommandReceipts[stagedScopeKey], &descriptor) != nil ||
			closures[descriptor.Binding.ScopeID][node.ID] != node {
			return fmt.Errorf("owned marker occurs outside its declared closure")
		}
		if node.ID != descriptor.Binding.RootID && len(node.CommandReceipts) != 1 {
			return fmt.Errorf("command history must live on its owned root")
		}
	}
	return nil
}
