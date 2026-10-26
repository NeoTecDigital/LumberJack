// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/sha256"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func validateEnrollmentDescriptor(descriptor stagedDescriptor) error {
	values := []string{descriptor.ProfileID, descriptor.ProfileRevision, descriptor.ProfileDigest}
	populated := 0
	for _, value := range values {
		if value != "" {
			populated++
		}
	}
	if populated == 0 {
		return nil
	}
	if populated != 3 || !domainValidHash(descriptor.ProfileDigest) {
		return fmt.Errorf("closed all-or-none protected descriptor required")
	}
	if descriptor.Binding.ProductID != "manifest" || descriptor.Binding.ScopeID != enrollmentScopeID(descriptor.Binding.AccountID) {
		return fmt.Errorf("enrollment descriptor namespace mismatch")
	}
	return enrollmentIdentifiers(descriptor.Bounds.MaxIdentifierBytes, descriptor.ProfileID, descriptor.ProfileRevision)
}
func enrollmentDescriptor(binding stagedBinding, p *DomainProvisioningProfile) stagedDescriptor {
	return stagedDescriptor{Binding: binding, Bounds: p.Bounds, ProfileID: p.ProfileRef.ProfileID, ProfileRevision: p.ProfileRef.ProfileRevision, ProfileDigest: p.ProfileRef.ProfileDigest}
}
func descriptorProfile(descriptor stagedDescriptor) EnrollmentProfileRef {
	return EnrollmentProfileRef{descriptor.ProfileID, descriptor.ProfileRevision, descriptor.ProfileDigest}
}
func enrollmentCommand(actor EnrollmentVerified, binding stagedBinding) stagedCommand {
	r := actor.Request
	return stagedCommand{actor.PrincipalID, r.Scope.AccountID, binding.ScopeID, r.CommandID, r.ExpectedRevision, r.Operation, actor.RequestFingerprint}
}
func enrollmentACL(p *DomainProvisioningProfile, principal, kind string) domainACL {
	grants := p.OwnerGrants[kind]
	acl := domainACL{ContractRevision: "lj.domain.acl/1", Principals: map[string]map[string]domainGrant{principal: grants}}
	if kind == "root" {
		acl.CreateACLs = enrollmentCreateACLs(p, principal)
	}
	return acl
}
func enrollmentCreateACLs(p *DomainProvisioningProfile, principal string) map[string]domainACL {
	templates := map[string]domainACL{}
	for kind := range p.Layout.Kinds {
		if kind != "root" {
			templates[kind] = enrollmentACL(p, principal, kind)
		}
	}
	return templates
}
func newEnrollmentNode(id, kind, principal string) *core.Node {
	return &core.Node{ID: id, Kind: kind, Name: id, Type: core.BranchNode, Parents: map[string]string{}, Children: map[string]*core.Node{}, Metadata: map[string]interface{}{}, CommandReceipts: map[string]interface{}{}, CreatedBy: principal}
}
func (s *Server) allocateEnrollmentRoots(d *domainEngine, actor EnrollmentVerified) (*stagedScope, *stagedPending, error) {
	p := d.config.ProvisioningProfile
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return nil, nil, err
	}
	accountID, err := allocateEnrollmentID(index)
	if err != nil {
		return nil, nil, err
	}
	rootID, err := allocateEnrollmentID(index)
	if err != nil || rootID == accountID {
		return nil, nil, fmt.Errorf("actual root allocation collision")
	}
	binding := stagedBinding{"manifest", "manifest-binding/0.2", enrollmentScopeID(actor.Scope.AccountID), actor.Scope.AccountID, accountID, rootID}
	descriptor := enrollmentDescriptor(binding, p)
	owner := enrollmentOwnerPrincipal(actor)
	account := newEnrollmentNode(accountID, p.AccountRootKind, owner)
	root := newEnrollmentNode(rootID, p.Layout.Kinds["root"], owner)
	if actor.Request.Administration != nil {
		account.Name, root.Name = actor.Request.Administration.Name, actor.Request.Administration.Name
	}
	account.Parents[s.forest.ID] = s.forest.Name
	root.Parents[account.ID], account.Children[root.ID] = account.Name, root
	account.Metadata[p.Layout.Fields["accountId"]] = actor.Scope.AccountID
	root.Metadata, err = enrollmentRootMetadata(d, actor)
	if err != nil {
		return nil, nil, err
	}
	root.CommandReceipts[stagedScopeKey] = descriptor
	scope := &stagedScope{descriptor: descriptor}
	pending, err := makeEnrollmentPending(scope, account, root, actor)
	return scope, pending, err
}
func allocateEnrollmentID(index map[string]*core.Node) (string, error) {
	id, err := newDomainID()
	if err != nil || index[id] != nil {
		return "", fmt.Errorf("actual fresh native ID unavailable")
	}
	return id, nil
}
func enrollmentRootMetadata(d *domainEngine, actor EnrollmentVerified) (map[string]interface{}, error) {
	p := d.config.ProvisioningProfile
	var catalog interface{}
	_ = DecodeDomainJSON(p.Layout.CatalogRef, &catalog)
	acl, err := enrollmentACLValue(enrollmentAdministrationACL(p, actor))
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{p.Layout.Fields["accountId"]: actor.Scope.AccountID, p.Layout.Fields["roleOrder"]: []string{}, p.Layout.Fields["roleCatalogRef"]: catalog, d.config.ACLMetadataKey: acl}, nil
}
func makeEnrollmentPending(scope *stagedScope, account, root *core.Node, actor EnrollmentVerified) (*stagedPending, error) {
	record, err := enrollmentRecord(actor)
	if err != nil {
		return nil, err
	}
	raw, err := CanonicalDomainJSON(record)
	if err != nil {
		return nil, err
	}
	revision, err := validateOwnedCandidate(root, scope.descriptor.Bounds)
	if err != nil {
		return nil, err
	}
	command := enrollmentCommand(actor, scope.descriptor.Binding)
	targets := []stagedTarget{{NodeID: root.ID, Kind: root.Kind, Fields: []string{"acl"}}}
	receipt := stagedReceipt{Version: 1, Command: command, Fingerprint: stagedCommandFingerprint(scope.descriptor.Binding, command), AfterRevision: revision, Targets: targets, EnrollmentRecord: raw}
	if err = validateEnrollmentReceipt(scope.descriptor.Binding, receipt, scope.descriptor.Bounds.MaxScopeBytes); err != nil {
		return nil, err
	}
	key := stagedCommandKey(command)
	root.CommandReceipts[key] = receipt
	if _, err = validateOwnedCandidate(root, scope.descriptor.Bounds); err != nil {
		return nil, err
	}
	return &stagedPending{provisionAccount: account, root: root, nodes: map[string]*core.Node{account.ID: account, root.ID: root}, receipt: receipt, key: key}, nil
}
func (s *Server) enrollmentOverlayForestLocked(overlay map[string]*core.Node) *core.Node {
	forest := enrollmentForestShell(s.forest)
	forest.Children = make(map[string]*core.Node, len(s.forest.Children))
	for id, child := range s.forest.Children {
		forest.Children[id] = child
	}
	for _, scope := range s.stagedScopes {
		if scope.pending != nil && scope.pending.provisionAccount != nil {
			account := scope.pending.provisionAccount
			forest.Children[account.ID] = account
		}
	}
	return forest
}
func (s *Server) publishProvisionLocked(scope *stagedScope, pending *stagedPending, stamp stagedDurableStamp) error {
	account := pending.provisionAccount
	if s.forest.Children[account.ID] != nil {
		return fmt.Errorf("new account collision before publication")
	}
	if scope.descriptor.Binding.ProductID == "momentum" {
		p := s.personalSource.Load()
		if p == nil {
			return fmt.Errorf("actual personal source missing")
		}
		return p.publishPersonalLocked(scope, pending, stamp)
	}
	if s.domain != nil {
		if err := registerEnrollmentScopeLocked(s.domain, scope.descriptor); err != nil {
			return err
		}
	}
	s.forest.Children[account.ID] = account
	scope.pending, scope.reconciled, scope.configured = nil, true, true
	live, err := encodeState(s.forest)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(live)
	s.lastHash = append([]byte(nil), hash[:]...)
	return nil
}

func enrollmentACLValue(acl domainACL) (interface{}, error) {
	raw, err := CanonicalDomainJSON(acl)
	if err != nil {
		return nil, err
	}
	var value interface{}
	err = DecodeDomainJSON(raw, &value)
	return value, err
}
func enrollmentForestShell(n *core.Node) *core.Node {
	return &core.Node{ID: n.ID, Type: n.Type, Kind: n.Kind, Name: n.Name, Parents: n.Parents, Metadata: n.Metadata, CommandReceipts: n.CommandReceipts, PersonalBindings: n.PersonalBindings,
		Events: n.Events, PlannedEvents: n.PlannedEvents, Users: n.Users, Entries: n.Entries, Attachments: n.Attachments,
		Correspondence: n.Correspondence, ApplicationSessions: n.ApplicationSessions, Subscriptions: n.Subscriptions,
		Conversations: n.Conversations, AccessPolicies: n.AccessPolicies, AccessGrants: n.AccessGrants, AccountSecurity: n.AccountSecurity,
		MFAChallenges: n.MFAChallenges, CreatedBy: n.CreatedBy, CreatedAt: n.CreatedAt, ModifiedBy: n.ModifiedBy, ModifiedAt: n.ModifiedAt}
}
