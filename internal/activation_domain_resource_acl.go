// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

func (s *Server) prepareEnrollmentACL(d *domainEngine, entry *domainEntry) (stagedPreparation, error) {
	actor := entry.enrollment.actor
	owned, present := d.lookupDomainScope(actor.Scope)
	if !present || !domainV2(owned) {
		return stagedPreparation{}, fmt.Errorf("actual v2 root registration required")
	}
	d.bindEnrollmentEntry(entry, enrollmentDescriptor(owned.Binding, d.config.ProvisioningProfile), "")
	command := enrollmentCommand(actor, owned.Binding)
	authorize := s.enrollmentAuthorizer(d, entry)
	build := func(view stagedView) (stagedDelta, error) { return buildEnrollmentACLDelta(d, entry, view) }
	prepared, err := s.prepareOwnedCommand(command, authorize, build)
	if err != nil {
		return prepared, err
	}
	s.forestMutex.RLock()
	scope := s.stagedScopes[owned.Binding.ScopeID]
	receipt, historyErr := s.enrollmentHistoryLocked(scope, prepared.pair.Key)
	if historyErr == nil {
		historyErr = validateEnrollmentReplay(scope, receipt, actor)
	}
	s.forestMutex.RUnlock()
	if historyErr != nil {
		return stagedPreparation{}, historyErr
	}
	d.bindEnrollmentEntry(entry, scope.descriptor, prepared.pair.Key)
	return prepared, nil
}
func (s *Server) enrollmentAuthorizer(d *domainEngine, entry *domainEntry) stagedAuthorizer {
	return func(access stagedAccess) error {
		if err := d.enrollmentLive(entry); err != nil {
			return err
		}
		if access.Binding != entry.owned.Binding || access.PrincipalID != entry.lease.PrincipalID || access.Action != entry.enrollment.input.Request.Operation {
			return fmt.Errorf("immutable enrollment access mismatch")
		}
		if len(access.Fields) > 0 && !domainEqual(access.Fields, []string{d.config.ACLMetadataKey}) {
			return fmt.Errorf("enrollment may only change explicit resource ACL")
		}
		return s.authorizeEnrollmentRootLocked(d, entry)
	}
}
func (s *Server) authorizeEnrollmentRootLocked(d *domainEngine, entry *domainEntry) error {
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return err
	}
	root := index[entry.owned.Binding.RootID]
	scope := s.stagedScopes[entry.owned.Binding.ScopeID]
	if scope != nil && scope.pending != nil && scope.pending.provisionAccount != nil {
		root = scope.pending.root
	}
	if root == nil {
		return fmt.Errorf("actual current native root absent")
	}
	policy := &domainOwnerPolicy{key: d.config.ACLMetadataKey}
	acl, err := policy.acl(DomainRecord{ID: root.ID, Kind: root.Kind, Metadata: root.Metadata})
	if err != nil {
		return err
	}
	actor := entry.enrollment.actor
	if actor.Request.Administration != nil {
		account := index[entry.owned.Binding.AccountRootID]
		if scope != nil && scope.pending != nil && scope.pending.provisionAccount != nil {
			account = scope.pending.provisionAccount
		}
		return s.authorizeEnrollmentAdministrationLocked(d, entry, account, root, acl)
	}
	grant, present := acl.Principals[actor.PrincipalID][actor.Request.Operation]
	if !present || !domainContains(grant.Fields, "acl") || grant.TargetGrantRevision != "" {
		return fmt.Errorf("current native owner enrollment action denied")
	}
	return nil
}
func buildEnrollmentACLDelta(d *domainEngine, entry *domainEntry, view stagedView) (stagedDelta, error) {
	if err := validateEnrollmentResponseBound(d, entry, view.Revision); err != nil {
		return stagedDelta{}, err
	}
	record, err := enrollmentRecord(entry.enrollment.actor)
	if err != nil {
		return stagedDelta{}, err
	}
	raw, err := CanonicalDomainJSON(record)
	if err != nil {
		return stagedDelta{}, err
	}
	delta := stagedDelta{EnrollmentRecord: raw}
	writes := newEnrollmentACLWrites(d, entry, view.Records[entry.owned.Binding.RootID])
	for _, native := range view.Records {
		write, err := writes.of(native)
		if err != nil {
			return stagedDelta{}, err
		}
		if write != nil {
			delta.Writes = append(delta.Writes, *write)
		}
	}
	if len(delta.Writes) == 0 {
		return stagedDelta{}, fmt.Errorf("known native graph absent")
	}
	return delta, nil
}
func enrollmentSemanticKind(layout DomainLayout, native string) string {
	for kind, value := range layout.Kinds {
		if value == native {
			return kind
		}
	}
	return ""
}
func (s *Server) validateEnrollmentCurrentLocked(d *domainEngine, entry *domainEntry) error {
	if err := d.enrollmentLive(entry); err != nil {
		return err
	}
	if err := s.authorizeEnrollmentRootLocked(d, entry); err != nil {
		return err
	}
	scope := s.stagedScopes[entry.owned.Binding.ScopeID]
	if scope == nil {
		return errStagedUnconfigured
	}
	receipt, err := s.enrollmentHistoryLocked(scope, entry.receiptKey)
	if err != nil {
		return err
	}
	if err = validateEnrollmentReplay(scope, receipt, entry.enrollment.actor); err != nil {
		return err
	}
	if entry.enrollment.actor.Request.Operation == EnrollmentReadGrant {
		return s.validateEnrollmentReadPinLocked(d, entry)
	}
	return nil
}
func (s *Server) validateEnrollmentReadPinLocked(d *domainEngine, entry *domainEntry) error {
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return err
	}
	scope := s.stagedScopes[entry.owned.Binding.ScopeID]
	root := index[entry.owned.Binding.RootID]
	if scope.pending != nil {
		root = scope.pending.root
	}
	nodes, err := stagedClosure(root, entry.owned.Bounds)
	if err != nil {
		return err
	}
	target := entry.enrollment.actor.PrincipalReference
	reader := newDomainACLReader(d.config.ACLMetadataKey, entry.owned, DomainRecord{ID: root.ID, Kind: root.Kind, Metadata: root.Metadata})
	for _, node := range nodes {
		if enrollmentSemanticKind(entry.owned.Layout, node.Kind) == "" {
			continue
		}
		acl, err := reader.acl(DomainRecord{ID: node.ID, Kind: node.Kind, Metadata: node.Metadata})
		if err != nil {
			return err
		}
		if !currentEnrollmentReadPins(entry, acl, enrollmentSemanticKind(entry.owned.Layout, node.Kind), target) || !currentEnrollmentTemplatePins(entry, acl, target) {
			return fmt.Errorf("native read grant was removed/replaced after command")
		}
	}
	return nil
}
