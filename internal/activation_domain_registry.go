// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sort"
)

func registerEnrollmentScopeLocked(d *domainEngine, descriptor stagedDescriptor) error {
	p := d.config.ProvisioningProfile
	if p == nil || descriptorProfile(descriptor) != p.ProfileRef || descriptor.Bounds != p.Bounds {
		return fmt.Errorf("current protected profile does not own paired descriptor")
	}
	owned := DomainOwnedScope{Binding: descriptor.Binding, Bounds: descriptor.Bounds, Layout: p.Layout}
	scope := DomainScope{descriptor.Binding.AccountID, descriptor.Binding.ProductID}
	d.mu.Lock()
	defer d.mu.Unlock()
	if previous, present := d.scopes[scope]; present {
		if previous.Binding != owned.Binding {
			return fmt.Errorf("canonical account has ambiguous actual native roots")
		}
		return nil
	}
	if len(d.scopes) >= d.config.MaxResources {
		return fmt.Errorf("actual scope capacity reached")
	}
	d.scopes[scope] = owned
	d.rootGeneration++
	return nil
}
func (s *Server) restoreDomainRegistry(d *domainEngine) error {
	permit, err := s.sourceFence().beginWrite(context.Background(), "restore-domain-registry/"+d.epoch)
	if err != nil {
		return err
	}
	err = s.restoreDomainRegistryWithPermit(d)
	permit.noEffect(err == nil)
	return err
}
func (s *Server) restoreDomainRegistryWithPermit(d *domainEngine) error {
	s.forestMutex.Lock()
	defer s.forestMutex.Unlock()
	for _, scope := range s.stagedScopes {
		if scope.descriptor.ProfileID == "" {
			continue
		}
		if !scope.reconciled {
			return fmt.Errorf("enrollment descriptor has no reconciled durable state")
		}
		if err := s.validateEnrollmentRegistrationLocked(d, scope); err != nil {
			return err
		}
		if err := registerEnrollmentScopeLocked(d, scope.descriptor); err != nil {
			return err
		}
		scope.configured = true
	}
	return nil
}
func (s *Server) validateEnrollmentRegistrationLocked(d *domainEngine, scope *stagedScope) error {
	p := d.config.ProvisioningProfile
	if p == nil || descriptorProfile(scope.descriptor) != p.ProfileRef || scope.descriptor.Bounds != p.Bounds {
		return fmt.Errorf("unrecognized protected paired profile")
	}
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return err
	}
	root := index[scope.descriptor.Binding.RootID]
	if root == nil || root.Kind != p.Layout.Kinds["root"] || root.Metadata[p.Layout.Fields["accountId"]] != scope.descriptor.Binding.AccountID {
		return fmt.Errorf("real native root identity mismatch")
	}
	catalog, err := CanonicalDomainJSON(root.Metadata[p.Layout.Fields["roleCatalogRef"]])
	if err != nil {
		return err
	}
	expected, err := CanonicalDomainJSON(p.Layout.CatalogRef)
	if err != nil || string(catalog) != string(expected) {
		return fmt.Errorf("native catalog pin mismatch on recovery")
	}
	return validateEnrollmentProvisionHistory(scope, root.CommandReceipts)
}
func validateEnrollmentProvisionHistory(scope *stagedScope, receipts map[string]interface{}) error {
	count := 0
	for key, raw := range receipts {
		if key == stagedScopeKey {
			continue
		}
		var receipt stagedReceipt
		if err := decodeStagedInternal(raw, &receipt); err != nil {
			return err
		}
		if receipt.Command.Action != EnrollmentProvision {
			continue
		}
		if err := validateEnrollmentReceipt(scope.descriptor.Binding, receipt, scope.descriptor.Bounds.MaxScopeBytes); err != nil {
			return err
		}
		if len(receipt.EnrollmentRecord) == 0 || key != stagedCommandKey(receipt.Command) {
			return fmt.Errorf("actual provisioning pair absent")
		}
		record, err := decodeEnrollmentRecord(receipt.EnrollmentRecord, scope.descriptor.Bounds.MaxScopeBytes)
		if err != nil || record.Request.ProfileRef != descriptorProfile(scope.descriptor) {
			return fmt.Errorf("provision pair/profile mismatch")
		}
		count++
	}
	if count != 1 {
		return fmt.Errorf("unique real provision command required")
	}
	return nil
}
func (d *domainEngine) enrollmentCapacity() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	scopes := map[DomainScope]bool{}
	for scope := range d.scopes {
		scopes[scope] = true
	}
	for _, entry := range d.entries {
		if entry.enrollment != nil && entry.owned.Binding.RootID != "" {
			scopes[entry.lease.Scope] = true
		}
	}
	return len(scopes) < d.config.MaxResources
}
func (d *domainEngine) bindEnrollmentEntry(entry *domainEntry, descriptor stagedDescriptor, pendingKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry.owned = DomainOwnedScope{Binding: descriptor.Binding, Bounds: descriptor.Bounds, Layout: d.config.ProvisioningProfile.Layout}
	entry.lease.Binding = DomainBinding{entry.lease.Scope, descriptor.Binding.RootID, descriptor.Binding.BindingRevision}
	entry.pendingKey, entry.receiptKey = pendingKey, pendingKey
	d.rootGeneration++
}
func (d *domainEngine) clearEnrollmentPending(entry *domainEntry) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry.pendingKey, entry.receiptKey = "", ""
	entry.owned = DomainOwnedScope{}
	entry.lease.Binding = DomainBinding{Scope: entry.lease.Scope}
	d.rootGeneration++
}
func enrollmentOwnerControl(d *domainEngine, input DomainControl) error {
	if input.Epoch != d.epoch || input.HostID != d.config.HostID || subtle.ConstantTimeCompare([]byte(input.ChannelToken), []byte(d.config.OwnerControlToken)) != 1 {
		return fmt.Errorf("private root owner channel denied")
	}
	if !domainFinite(input.ValidUntil) || input.ValidUntil <= domainNow() {
		return fmt.Errorf("finite current root-control deadline required")
	}
	return enrollmentIdentifiers(d.config.MaxRequestBytes, input.PrincipalID, input.SessionID)
}
func (s *Server) enrollmentRootControl(d *domainEngine, input DomainControl) (DomainControlResult, error) {
	if err := enrollmentOwnerControl(d, input); err != nil {
		return DomainControlResult{}, err
	}
	key := enrollmentSessionKey{input.PrincipalID, input.SessionID}
	if input.Action == "roots.snapshot" {
		if err := d.source.fenceSession(key, d.config.MaxLeases); err != nil {
			return DomainControlResult{}, err
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := enrollmentOwnerControl(d, input); err != nil {
		return DomainControlResult{}, err
	}
	switch input.Action {
	case "roots.snapshot":
		if err := fenceEnrollmentSessionLocked(d, key); err != nil {
			return DomainControlResult{}, err
		}
		return DomainControlResult{Value: EnrollmentRootSnapshot{d.rootGeneration, enrollmentRootsLocked(d, key)}}, nil
	case "roots.state":
		return DomainControlResult{Value: map[string]interface{}{"fenced": d.sessionFences[key], "drained": enrollmentSessionDrainedLocked(d, key), "generation": d.rootGeneration}}, nil
	case "roots.recheck":
		actual := EnrollmentRootSnapshot{d.rootGeneration, enrollmentRootsLocked(d, key)}
		if !d.sessionFences[key] || input.RootSnapshot == nil || !domainEqual(*input.RootSnapshot, actual) || !enrollmentSessionDrainedLocked(d, key) {
			return DomainControlResult{}, fmt.Errorf("actual session roots changed/not drained")
		}
		return DomainControlResult{Value: map[string]bool{"verified": true}}, nil
	}
	return DomainControlResult{}, fmt.Errorf("unsupported private root control")
}
func enrollmentRootsLocked(d *domainEngine, key enrollmentSessionKey) []EnrollmentRootRef {
	roots := []EnrollmentRootRef{}
	for scope, owned := range d.scopes {
		binding := DomainBinding{scope, owned.Binding.RootID, owned.Binding.BindingRevision}
		roots = append(roots, EnrollmentRootRef{Scope: scope, Binding: &binding, Epoch: d.epoch, HostID: d.config.HostID})
	}
	for id, entry := range d.entries {
		if entry.lease.PrincipalID != key.PrincipalID || entry.lease.SessionID != key.SessionID || entry.finished {
			continue
		}
		if !entry.executing && entry.pendingKey == "" && entry.owned.Binding.RootID != "" {
			continue
		}
		var binding *DomainBinding
		if entry.lease.Binding.RootID != "" {
			copy := entry.lease.Binding
			binding = &copy
		}
		roots = append(roots, EnrollmentRootRef{Scope: entry.lease.Scope, Binding: binding, Epoch: d.epoch, HostID: d.config.HostID, LeaseID: id, Pending: true})
	}
	sort.Slice(roots, func(i, j int) bool { return enrollmentRootSortKey(roots[i]) < enrollmentRootSortKey(roots[j]) })
	return roots
}
func enrollmentRootSortKey(root EnrollmentRootRef) string {
	raw, _ := CanonicalDomainJSON(root)
	return string(raw)
}
func enrollmentSessionDrainedLocked(d *domainEngine, key enrollmentSessionKey) bool {
	if !d.source.sessionSettled(key) {
		return false
	}
	for scope := range d.scopes {
		if !d.closed[DomainGateKey{key.PrincipalID, key.SessionID, scope}] {
			return false
		}
	}
	for _, entry := range d.entries {
		if entry.lease.PrincipalID == key.PrincipalID && entry.lease.SessionID == key.SessionID && !entry.finished {
			return false
		}
	}
	return true
}

func fenceEnrollmentSessionLocked(d *domainEngine, key enrollmentSessionKey) error {
	if d.sessionFences[key] {
		return nil
	}
	if len(d.sessionFences) >= d.config.MaxLeases {
		return fmt.Errorf("retained session fence capacity reached")
	}
	d.sessionFences[key] = true
	d.rootGeneration++
	return nil
}
