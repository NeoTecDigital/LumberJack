// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func validateStagedBounds(bounds stagedBounds) error {
	values := []int{bounds.MaxNodes, bounds.MaxChanges, bounds.MaxReceipts,
		bounds.MaxIdentifierBytes, bounds.MaxValueDepth, bounds.MaxScopeBytes, bounds.MaxSnapshotBytes}
	for _, value := range values {
		if value <= 0 {
			return fmt.Errorf("every owned bound must be explicitly positive")
		}
	}
	return nil
}

func validateStagedIdentifiers(bounds stagedBounds, identifiers ...string) error {
	for _, id := range identifiers {
		if id == "" || len(id) > bounds.MaxIdentifierBytes || !utf8.ValidString(id) {
			return fmt.Errorf("owned identifier is empty, invalid or exceeds its bound")
		}
	}
	return nil
}

func isStagedNode(node *core.Node) bool {
	if node == nil {
		return false
	}
	_, marked := node.CommandReceipts[stagedScopeKey]
	return marked
}

func stagedForestIndex(root *core.Node) (map[string]*core.Node, error) {
	index := map[string]*core.Node{}
	seen := map[*core.Node]bool{}
	queue := []*core.Node{root}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if node == nil || seen[node] {
			continue
		}
		seen[node] = true
		if previous := index[node.ID]; previous != nil && previous != node {
			return nil, fmt.Errorf("native ID has conflicting objects: %s", node.ID)
		}
		index[node.ID] = node
		for _, child := range node.Children {
			queue = append(queue, child)
		}
	}
	return index, nil
}

func stagedClosure(root *core.Node, bounds stagedBounds) (map[string]*core.Node, error) {
	if root == nil {
		return nil, fmt.Errorf("owned root is missing")
	}
	nodes, err := stagedForestIndex(root)
	if err != nil {
		return nil, err
	}
	if len(nodes) > bounds.MaxNodes {
		return nil, fmt.Errorf("owned closure exceeds node bound")
	}
	for _, node := range nodes {
		if err := validateStagedProfile(node, bounds); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func validateStagedOwnership(index, nodes map[string]*core.Node, descriptor stagedDescriptor) error {
	binding := descriptor.Binding
	if index[binding.AccountRootID] == nil || nodes[binding.AccountRootID] != nil {
		return fmt.Errorf("owned account root is missing or inside its own data closure")
	}
	for _, parent := range index {
		if err := validateStagedIncoming(parent, nodes, descriptor); err != nil {
			return err
		}
	}
	for _, node := range nodes {
		if err := validateStagedParents(index, nodes, node, descriptor.Binding); err != nil {
			return err
		}
	}
	return nil
}

func validateStagedParents(index, nodes map[string]*core.Node, node *core.Node, binding stagedBinding) error {
	for id, name := range node.Parents {
		parent := index[id]
		boundary := node.ID == binding.RootID && id == binding.AccountRootID
		if parent == nil || (!boundary && nodes[id] == nil) || parent.Name != name || parent.Children[node.ID] != node {
			return fmt.Errorf("owned parent reference is not an accepted real edge")
		}
	}
	return nil
}

func validateStagedIncoming(parent *core.Node, nodes map[string]*core.Node, descriptor stagedDescriptor) error {
	for key, child := range parent.Children {
		if child == nil || nodes[child.ID] == nil {
			continue
		}
		inside := nodes[parent.ID] != nil
		boundary := child.ID == descriptor.Binding.RootID && parent.ID == descriptor.Binding.AccountRootID
		if (!inside && !boundary) || key != child.ID || nodes[child.ID] != child {
			return fmt.Errorf("owned closure has an external alias or conflicting edge")
		}
		if child.Parents[parent.ID] != parent.Name {
			return fmt.Errorf("owned edge has inconsistent parent identity")
		}
	}
	return nil
}

func (s *Server) prepareStagedScopeLocked(descriptor stagedDescriptor) (*stagedScope, error) {
	if err := validateStagedBounds(descriptor.Bounds); err != nil {
		return nil, err
	}
	binding := descriptor.Binding
	if err := validateStagedIdentifiers(descriptor.Bounds, binding.ScopeID, binding.AccountID, binding.AccountRootID, binding.RootID); err != nil {
		return nil, err
	}
	index, err := stagedForestIndex(s.forest)
	if err != nil || index[binding.RootID] == nil {
		return nil, fmt.Errorf("owned root is missing or native identities conflict")
	}
	nodes, err := stagedClosure(index[binding.RootID], descriptor.Bounds)
	if err != nil {
		return nil, err
	}
	if err := validateStagedOwnership(index, nodes, descriptor); err != nil {
		return nil, err
	}
	if err := validateStagedSetup(nodes, descriptor); err != nil {
		return nil, err
	}
	if s.stagedScopes == nil {
		s.stagedScopes = map[string]*stagedScope{}
	}
	scope := s.stagedScopes[binding.ScopeID]
	if scope != nil && scope.descriptor != descriptor {
		return nil, fmt.Errorf("owned scope binding/bounds cannot be silently replaced")
	}
	if scope == nil {
		scope = &stagedScope{descriptor: descriptor}
	}
	if err := markStagedClosure(nodes, descriptor); err != nil {
		return nil, err
	}
	s.stagedScopes[binding.ScopeID] = scope
	return scope, nil
}

func markStagedClosure(nodes map[string]*core.Node, descriptor stagedDescriptor) error {
	for _, node := range nodes {
		if err := validateStagedMarker(node, descriptor); err != nil {
			return err
		}
	}
	for _, node := range nodes {
		if node.CommandReceipts == nil {
			node.CommandReceipts = map[string]interface{}{}
		}
		node.CommandReceipts[stagedScopeKey] = descriptor
	}
	return nil
}

func validateStagedMarker(node *core.Node, descriptor stagedDescriptor) error {
	if marker, present := node.CommandReceipts[stagedScopeKey]; present {
		var previous stagedDescriptor
		if decodeStagedInternal(marker, &previous) != nil || previous != descriptor {
			return fmt.Errorf("owned marker conflicts with the accepted descriptor")
		}
	}
	for key := range node.CommandReceipts {
		if key != stagedScopeKey && !isStagedReceiptKey(key) {
			return fmt.Errorf("new owned namespace contains legacy receipts")
		}
	}
	return nil
}

func (s *Server) configureStagedScope(binding stagedBinding, bounds stagedBounds) error {
	s.forestMutex.Lock()
	scope, err := s.prepareStagedScopeLocked(stagedDescriptor{Binding: binding, Bounds: bounds})
	if err != nil {
		s.forestMutex.Unlock()
		return err
	}
	snapshot, err := s.encodeSnapshotLocked(s.statePath(), false)
	if err == nil && len(snapshot.data) > bounds.MaxSnapshotBytes {
		err = fmt.Errorf("owned setup snapshot exceeds its explicit byte bound")
	}
	s.forestMutex.Unlock()
	if err != nil {
		return err
	}
	pair := snapshot.pairs[stagedPairKey(binding.ScopeID, stagedScopeKey)]
	if _, err := s.stateWriter.commitPaired(snapshot, pair); err != nil {
		return err
	}
	s.forestMutex.Lock()
	scope.configured, scope.reconciled = true, true
	s.forestMutex.Unlock()
	return nil
}

func decodeStagedInternal(value interface{}, target interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return strictActivationJSON(data, target)
}
