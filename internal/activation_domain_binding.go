// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"fmt"
)

func (s *Server) DomainResolve(ctx context.Context, input DomainInput) (DomainIntent, error) {
	d, err := s.domainEngine()
	if err != nil {
		return DomainIntent{}, err
	}
	s.forestMutex.RLock()
	defer s.forestMutex.RUnlock()
	intent, _, _, err := s.resolveDomainLocked(d, input)
	return intent, err
}
func (s *Server) resolveDomainLocked(d *domainEngine, input DomainInput) (DomainIntent, DomainOwnedScope, DomainView, error) {
	if len(input.Body) == 0 || len(input.Body) > d.config.MaxRequestBytes {
		return DomainIntent{}, DomainOwnedScope{}, DomainView{}, fmt.Errorf("bounded canonical body required")
	}
	if err := checkDomainJSON(input.Body); err != nil {
		return DomainIntent{}, DomainOwnedScope{}, DomainView{}, err
	}
	var envelope struct {
		Scope DomainScope `json:"scope"`
	}
	if err := json.Unmarshal(input.Body, &envelope); err != nil {
		return DomainIntent{}, DomainOwnedScope{}, DomainView{}, err
	}
	owned, present := d.scopes[envelope.Scope]
	if !present {
		return DomainIntent{}, owned, DomainView{}, fmt.Errorf("native owner binding absent")
	}
	view, err := s.domainViewLocked(owned)
	if err != nil {
		return DomainIntent{}, owned, view, err
	}
	if input.Mode == "read" && s.stagedScopes[owned.Binding.ScopeID].pending != nil {
		return DomainIntent{}, owned, view, errStagedPending
	}
	intent, err := d.products[envelope.Scope.Product].Resolve(input, owned, view)
	if err == nil {
		err = validateDomainIntent(d, intent, owned, input)
	}
	return intent, owned, view, err
}
func (s *Server) domainViewLocked(owned DomainOwnedScope) (DomainView, error) {
	scope := s.stagedScopes[owned.Binding.ScopeID]
	if scope == nil || !scope.configured || !scope.reconciled || scope.descriptor.Binding != owned.Binding {
		return DomainView{}, errStagedUnconfigured
	}
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return DomainView{}, err
	}
	root := index[owned.Binding.RootID]
	nodes, err := stagedClosure(root, owned.Bounds)
	if err != nil {
		return DomainView{}, err
	}
	revision, err := stagedContentRevision(root)
	if err != nil {
		return DomainView{}, err
	}
	native, err := newStagedView(scope, nodes, revision, map[string]bool{})
	if err != nil {
		return DomainView{}, err
	}
	return domainView(native, ""), nil
}
func domainView(native stagedView, aclKey string) DomainView {
	return DomainView{Binding: native.Binding, Revision: native.Revision, Records: native.Records, AllocateID: native.AllocateID, ACLMetadataKey: aclKey}
}
func validateDomainIntent(d *domainEngine, intent DomainIntent, owned DomainOwnedScope, input DomainInput) error {
	binding := owned.Binding
	scope := DomainScope{binding.AccountID, binding.ProductID}
	expected := DomainBinding{scope, binding.RootID, binding.BindingRevision}
	if intent.Scope != scope || intent.Binding != expected || intent.Mode != input.Mode || intent.Method != input.Method || intent.Target != input.Target || !domainValidHash(intent.RequestFingerprint) {
		return fmt.Errorf("intent binding mismatch")
	}
	if len(intent.Resources) == 0 || len(intent.Resources) > d.config.MaxResources || len(intent.Fields) != len(intent.Resources) {
		return fmt.Errorf("bounded complete resource/field intent required")
	}
	for _, set := range intent.Fields {
		if set.Resource.AccountID != scope.AccountID || len(set.Fields) == 0 || len(set.Fields) > d.config.MaxFields {
			return fmt.Errorf("explicit bounded resource fields required")
		}
	}
	return nil
}
func (d *domainEngine) authorizeIntentLocked(actor DomainVerified, view DomainView) error {
	operation := "read"
	if actor.Intent.Operation != nil {
		operation = *actor.Intent.Operation
	}
	for _, fields := range actor.Intent.Fields {
		record, present := view.Records[fields.Resource.ResourceID]
		if !present {
			return fmt.Errorf("current resource disappeared")
		}
		access := DomainAccess{Operation: operation, Kind: fields.Resource.Kind, Fields: fields.Fields, Reference: domainContains(fields.Fields, "reference")}
		if err := d.policy.AuthorizeLocked(actor, access, record); err != nil {
			return err
		}
	}
	return nil
}
func (s *Server) domainAuthorizer(d *domainEngine, entry *domainEntry) stagedAuthorizer {
	return func(access stagedAccess) error {
		if entry.actor.ExpiresAt <= domainNow() || access.Binding != entry.owned.Binding {
			return fmt.Errorf("current domain authority expired/rebound")
		}
		current, _, view, err := s.resolveDomainLocked(d, entry.input)
		if err != nil {
			return err
		}
		if !domainEqual(current, entry.intent) {
			return fmt.Errorf("current intent resources changed")
		}
		if err = d.authorizeIntentLocked(entry.actor, view); err != nil {
			return err
		}
		if access.NodeID == "" {
			return nil
		}
		return d.authorizeNativeTarget(entry, view, access)
	}
}
func (d *domainEngine) authorizeNativeTarget(entry *domainEntry, view DomainView, access stagedAccess) error {
	create := entry.intent.Operation != nil && isDomainDefinition(*entry.intent.Operation) && access.NodeID != entry.owned.Binding.RootID
	keys := append([]string(nil), access.Fields...)
	if create {
		keys = domainWithout(keys, d.config.ACLMetadataKey)
	}
	fields, err := entry.product.PublicFields(access.Kind, keys, entry.owned)
	if err != nil {
		return err
	}
	if create {
		return d.authorizeDefinitionTarget(entry, view, access, fields)
	}
	record, present := view.Records[access.NodeID]
	if !present {
		return fmt.Errorf("current native target absent")
	}
	return d.policy.AuthorizeLocked(entry.actor, DomainAccess{Operation: access.Action, Kind: access.Kind, Fields: fields}, record)
}

func (d *domainEngine) authorizeDefinitionTarget(entry *domainEntry, view DomainView, access stagedAccess, fields []string) error {
	kind := domainSemanticKind(entry.owned.Layout, access.Kind)
	root := view.Records[entry.owned.Binding.RootID]
	required := DomainAccess{Operation: access.Action, Kind: kind, Fields: fields, Create: true}
	if err := d.policy.AuthorizeLocked(entry.actor, required, root); err != nil {
		return err
	}
	record, present := view.Records[access.NodeID]
	if !present {
		acl, err := d.policy.CreateACLLocked(entry.actor, access.Action, kind, root)
		if err != nil {
			return err
		}
		record = DomainRecord{ID: access.NodeID, Kind: access.Kind, Metadata: map[string]interface{}{d.config.ACLMetadataKey: acl}}
	}
	required.Create = false
	return d.policy.AuthorizeLocked(entry.actor, required, record)
}

func domainWithout(fields []string, excluded string) []string {
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if field != excluded {
			result = append(result, field)
		}
	}
	return result
}
func domainSemanticKind(layout DomainLayout, native string) string {
	for kind, value := range layout.Kinds {
		if value == native {
			return kind
		}
	}
	return ""
}
func isDomainDefinition(operation string) bool {
	return len(operation) > 7 && operation[len(operation)-7:] == ".define"
}
