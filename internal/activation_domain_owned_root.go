// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"fmt"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// DomainOwnedRootSpec is a protected host's explicit request for one product root: the account
// container, the root and the root's metadata (its ACL), under the forest. Enrollment owns the
// Manifest roots; this is the provisioning operation for a product whose accounts the host owns.
type DomainOwnedRootSpec struct {
	Binding     stagedBinding          `json:"binding"`
	Bounds      stagedBounds           `json:"bounds"`
	AccountKind string                 `json:"accountKind"`
	RootKind    string                 `json:"rootKind"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DomainOwnedRootResult says what the call did: "created", or "replayed" for the same root.
type DomainOwnedRootResult struct {
	State  string `json:"state"`
	RootID string `json:"rootId"`
}

func validateOwnedRootSpec(spec DomainOwnedRootSpec) error {
	if spec.Binding.ProductID != "momentum" || spec.Binding.BindingRevision == "" {
		return fmt.Errorf("explicit host-owned product binding required")
	}
	if spec.AccountKind == "" || spec.RootKind == "" || spec.AccountKind == spec.RootKind || len(spec.Metadata) == 0 {
		return fmt.Errorf("explicit distinct kinds and root metadata required")
	}
	if spec.Binding.AccountRootID == spec.Binding.RootID {
		return fmt.Errorf("account container and root must be distinct")
	}
	if err := validateStagedBounds(spec.Bounds); err != nil {
		return err
	}
	return validateStagedIdentifiers(spec.Bounds, spec.Binding.ScopeID, spec.Binding.AccountID, spec.Binding.AccountRootID, spec.Binding.RootID, spec.AccountKind, spec.RootKind)
}

// ProvisionOwnedRoot creates the root durably, before the domain engine that will bind it exists,
// on a new or an existing forest. The same request again is a replay; a different root under the
// same identifiers is refused. Nothing is created without its acknowledged durable snapshot.
func (s *Server) ProvisionOwnedRoot(spec DomainOwnedRootSpec) (DomainOwnedRootResult, error) {
	if err := validateOwnedRootSpec(spec); err != nil {
		return DomainOwnedRootResult{}, err
	}
	permit, err := s.sourceFence().beginWrite(context.Background(), "provision-owned-root/"+sourceCommandKey(spec.Binding))
	if err != nil {
		return DomainOwnedRootResult{}, err
	}
	before := s.sourceForestRevision()
	result, err := s.provisionOwnedRootWithPermit(spec)
	if err != nil {
		permit.noEffect(before != "" && before == s.sourceForestRevision())
		return DomainOwnedRootResult{}, err
	}
	permit.finish(true, result.State == "created")
	return result, nil
}

type ownedRootPreparation struct {
	replayed bool
	pair     stagedPair
	snapshot stateSnapshot
	scope    *stagedScope
}

func (s *Server) provisionOwnedRootWithPermit(spec DomainOwnedRootSpec) (DomainOwnedRootResult, error) {
	prepared, err := s.prepareOwnedRoot(spec)
	if err != nil {
		return DomainOwnedRootResult{}, err
	}
	if prepared.replayed {
		return DomainOwnedRootResult{State: "replayed", RootID: spec.Binding.RootID}, nil
	}
	if _, err = s.stateWriter.commitPaired(prepared.snapshot, prepared.pair); err != nil {
		return DomainOwnedRootResult{}, err
	}
	s.forestMutex.Lock()
	prepared.scope.configured, prepared.scope.reconciled = true, true
	s.forestMutex.Unlock()
	return DomainOwnedRootResult{State: "created", RootID: spec.Binding.RootID}, nil
}

func (s *Server) prepareOwnedRoot(spec DomainOwnedRootSpec) (ownedRootPreparation, error) {
	s.forestMutex.Lock()
	defer s.forestMutex.Unlock()
	if s.domain != nil || s.domainConfiguring {
		return ownedRootPreparation{}, fmt.Errorf("owned roots are provisioned before the domain engine")
	}
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return ownedRootPreparation{}, err
	}
	descriptor := stagedDescriptor{Binding: spec.Binding, Bounds: spec.Bounds}
	if index[spec.Binding.RootID] != nil {
		return ownedRootPreparation{replayed: true}, validateOwnedRootReplay(index, spec, descriptor)
	}
	if index[spec.Binding.AccountRootID] != nil || s.stagedScopes[spec.Binding.ScopeID] != nil {
		return ownedRootPreparation{}, fmt.Errorf("owned root identifiers already name other native state")
	}
	account := s.attachOwnedRootLocked(spec)
	scope, snapshot, err := s.ownedRootSnapshotLocked(descriptor)
	if err != nil {
		delete(s.forest.Children, account.ID)
		delete(s.stagedScopes, spec.Binding.ScopeID)
		return ownedRootPreparation{}, err
	}
	pair := snapshot.pairs[stagedPairKey(spec.Binding.ScopeID, stagedScopeKey)]
	return ownedRootPreparation{pair: pair, snapshot: snapshot, scope: scope}, nil
}

func (s *Server) attachOwnedRootLocked(spec DomainOwnedRootSpec) *core.Node {
	account := newEnrollmentNode(spec.Binding.AccountRootID, spec.AccountKind, "")
	root := newEnrollmentNode(spec.Binding.RootID, spec.RootKind, "")
	for key, value := range spec.Metadata {
		root.Metadata[key] = value
	}
	account.Parents[s.forest.ID] = s.forest.Name
	root.Parents[account.ID], account.Children[root.ID] = account.Name, root
	s.forest.Children[account.ID] = account
	return account
}

func (s *Server) ownedRootSnapshotLocked(descriptor stagedDescriptor) (*stagedScope, stateSnapshot, error) {
	scope, err := s.prepareStagedScopeLocked(descriptor)
	if err != nil {
		return nil, stateSnapshot{}, err
	}
	snapshot, err := s.encodeSnapshotLocked(s.statePath(), false)
	if err == nil && len(snapshot.data) > descriptor.Bounds.MaxSnapshotBytes {
		err = fmt.Errorf("owned setup snapshot exceeds its explicit byte bound")
	}
	return scope, snapshot, err
}

func validateOwnedRootReplay(index map[string]*core.Node, spec DomainOwnedRootSpec, descriptor stagedDescriptor) error {
	root, account := index[spec.Binding.RootID], index[spec.Binding.AccountRootID]
	if account == nil || account.Kind != spec.AccountKind || root.Kind != spec.RootKind || account.Children[root.ID] != root {
		return fmt.Errorf("existing root is not this owned root")
	}
	var marker stagedDescriptor
	if decodeStagedInternal(root.CommandReceipts[stagedScopeKey], &marker) != nil || marker != descriptor {
		return fmt.Errorf("existing root is bound to another scope")
	}
	for key, value := range spec.Metadata {
		if !domainEqual(root.Metadata[key], value) {
			return fmt.Errorf("existing root metadata differs from this request")
		}
	}
	return nil
}
