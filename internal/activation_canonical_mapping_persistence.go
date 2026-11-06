// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
)

type canonicalMutationRecord struct {
	ContractRevision string `json:"contractRevision"`
	Operation        string `json:"operation"`
	MappingID        string `json:"mappingId"`
	StableSHA256     string `json:"stableSha256"`
}

func canonicalScopeID(mapping string) string {
	return "lj.personal.mapping/v1:" + sourceCommandKey(mapping)
}
func (p *personalSource) persistCanonical(ctx context.Context, e *canonicalSourceEntry, action string, state CanonicalState, expectedBinding *string) error {
	if p.canonicalEntryCurrent(e) != nil || e.authorityUntil <= domainNow() || e.write == nil || !e.write.owns(p.coordinator) {
		return sourceDenied()
	}
	p.server.forestMutex.Lock()
	err := p.prepareCanonicalLocked(e, action, state, expectedBinding)
	p.server.forestMutex.Unlock()
	if err != nil {
		return err
	}
	if e.durable != nil {
		return nil
	}
	pair, ok := e.prepared.pairs[stagedPairKey(e.scope.descriptor.Binding.ScopeID, e.pending.key)]
	if !ok {
		return sourceUnavailable()
	}
	stamp, err := p.server.stateWriter.commitPaired(e.prepared, pair)
	if err != nil {
		e.unknown = true
		e.write.finish(false, true)
		return sourceUnavailable()
	}
	if !e.write.owns(p.coordinator) || ctx.Err() != nil || e.authorityUntil <= domainNow() || p.currentCanonicalControl(e) != nil {
		e.unknown = true
		e.write.finish(false, true)
		return sourceUnavailable()
	}
	if err = p.server.publishOwnedPair(e.scope.descriptor.Binding.ScopeID, e.pending, stamp); err != nil {
		e.unknown = true
		e.write.finish(false, true)
		return sourceUnavailable()
	}
	e.durable = &stamp
	e.pending = nil
	return nil
}
func (p *personalSource) prepareCanonicalLocked(e *canonicalSourceEntry, action string, state CanonicalState, expected *string) error {
	if p.currentNativeControlLocked(e) != nil {
		return sourceDenied()
	}
	ledger, err := p.canonicalCandidateLedgerLocked()
	if err != nil {
		return err
	}
	digest := p.canonicalEffectDigest(e, action, expected)
	record, present := ledger.Mappings[e.mapping.MappingID]
	if !present && len(ledger.Mappings) >= p.config.Bounds.MaxBindings {
		return sourceUnavailable()
	}
	if present && !domainEqual(record.Mapping, e.mapping) {
		return sourceDenied()
	}
	historyKey := sourceCommandKey([]string{action, e.key.CommandID})
	if previous, ok := record.History[historyKey]; ok {
		if previous.StableSHA256 != digest || !domainEqual(previous.Expected, expected) {
			return sourceDenied()
		}
		return p.canonicalHistoryReplayLocked(e, previous)
	}
	if len(record.History) >= p.config.StagedBounds.MaxReceipts {
		return sourceUnavailable()
	}
	if action == "consent.establish" {
		record, err = p.candidateCanonicalConsent(e, ledger, state, record, present)
	} else {
		record, err = p.candidateCanonicalAttach(e, ledger, state, record, expected)
	}
	if err != nil {
		return err
	}
	return p.prepareCanonicalPairLocked(e, action, digest, historyKey, expected, ledger, record)
}
func (p *personalSource) prepareCanonicalPairLocked(e *canonicalSourceEntry, action, digest, historyKey string, expected *string, ledger *core.PersonalBindingLedger, record core.PersonalMappingRecord) error {
	var err error
	if record.History == nil {
		record.History = map[string]core.PersonalMappingHistory{}
	}
	scope, pending, err := p.canonicalPendingRootLocked(e, action, digest)
	if err != nil {
		return err
	}
	result, err := p.canonicalResult(e, action, record)
	if err != nil {
		return err
	}
	bindingRaw, _ := CanonicalDomainJSON(scope.descriptor.Binding)
	record.History[historyKey] = core.PersonalMappingHistory{action, e.key.CommandID, digest, expected, result, pending.key, bindingRaw}
	ledger.Mappings[e.mapping.MappingID] = record
	ledger.Revision = sourceCommandKey(ledger)
	e.scope, e.pending, e.ledger, e.result = scope, pending, ledger, result
	prepared, err := p.server.snapshotOwnedPreparationLocked(scope, pending, pending.key, false)
	if err != nil {
		scope.pending = nil
		e.pending = nil
		e.ledger = nil
		return err
	}
	e.prepared = prepared.snapshot
	return nil
}
func (p *personalSource) canonicalCandidateLedgerLocked() (*core.PersonalBindingLedger, error) {
	ledger := &core.PersonalBindingLedger{Bindings: map[string]core.PersonalBindingRecord{}, Consents: map[string]core.PersonalConsentRecord{}, Receipts: map[string]core.PersonalProvisionRecord{}, Mappings: map[string]core.PersonalMappingRecord{}}
	if current := p.server.forest.PersonalBindings; current != nil && sourceCanonicalCopy(current, ledger) != nil {
		return nil, sourceUnavailable()
	}
	if ledger.Mappings == nil {
		ledger.Mappings = map[string]core.PersonalMappingRecord{}
	}
	return ledger, nil
}
func (p *personalSource) candidateCanonicalConsent(e *canonicalSourceEntry, l *core.PersonalBindingLedger, state CanonicalState, record core.PersonalMappingRecord, present bool) (core.PersonalMappingRecord, error) {
	expected := e.key.ExpectedRevision
	if present && (expected == nil || *expected != record.ConsentRevision) {
		return record, sourceDenied()
	}
	if !present && expected != nil {
		return record, sourceDenied()
	}
	if !present && len(l.Consents) >= p.config.Bounds.MaxSources {
		return record, sourceUnavailable()
	}
	ref := record.ConsentRef
	var err error
	if !present {
		ref, err = newDomainID()
		if err != nil {
			return record, sourceUnavailable()
		}
	}
	m := e.mapping
	consent := core.PersonalConsentRecord{ConsentRef: ref, NativeOwnerID: m.Binding.OwnerRef.OwnerID, RootID: m.Binding.OwnerRef.RootID, Issuer: m.Issuer, Subject: m.Subject, MappingRef: m.MappingID, State: "active", CommandID: e.key.CommandID, CommandSHA256: e.key.StableCommandSHA256}
	consent.Revision = sourceCommandKey(consent)
	l.Consents[ref] = consent
	record.Mapping, record.Canonical, record.ConsentRef, record.ConsentRevision = m, state, ref, consent.Revision
	return record, nil
}
func (p *personalSource) candidateCanonicalAttach(e *canonicalSourceEntry, l *core.PersonalBindingLedger, state CanonicalState, r core.PersonalMappingRecord, expected *string) (core.PersonalMappingRecord, error) {
	if e.association == nil || e.enrollment == nil || r.ConsentRef == "" || !canonicalCurrentStateMatches(state, e.mapping) {
		return r, sourceDenied()
	}
	consent, present := l.Consents[r.ConsentRef]
	if !present || consent.State != "active" || !canonicalAssociationMatches(*e.association, r, consent, p.config) {
		return r, sourceDenied()
	}
	if r.Binding == nil && expected != nil {
		return r, sourceDenied()
	}
	if r.Binding != nil && (expected == nil || *expected != r.Binding.BindingRevision) {
		return r, sourceDenied()
	}
	id, revision := e.association.AssociationID, e.association.Revision
	ref := consent.ConsentRef
	b := e.mapping.Binding
	r.Binding = &core.PersonalBindingRecord{PrincipalID: b.PrincipalID, Account: b.Account, OwnerRef: b.OwnerRef, BindingRevision: sourceCommandKey([]interface{}{r.Mapping, *e.association, *e.enrollment, expected}), AccountRegistryRevision: *state.AccountRegistryRevision, Enrollment: *e.enrollment, AssociationID: &id, AssociationRevision: &revision, ConsentRef: &ref, OwnerKind: "existing"}
	r.Canonical = state
	return r, nil
}
func (p *personalSource) canonicalEffectDigest(e *canonicalSourceEntry, action string, expected *string) string {
	if action == "consent.establish" {
		return e.key.StableCommandSHA256
	}
	return sourceCommandKey(map[string]interface{}{"operation": action, "mapping": e.mapping, "commandId": e.key.CommandID, "association": e.association, "enrollmentRef": e.enrollment, "expectedBindingRevision": expected})
}
func (p *personalSource) canonicalPendingRootLocked(e *canonicalSourceEntry, action, digest string) (*stagedScope, *stagedPending, error) {
	root := p.server.forest.Children[e.facts.rootID]
	nodes, err := p.controlledSourceClosureLocked(e, root)
	if err != nil {
		return nil, nil, err
	}
	nodes, err = clonePreservedStagedNodes(nodes, p.config.StagedBounds)
	if err != nil {
		return nil, nil, err
	}
	clone := nodes[root.ID]
	scopeID := canonicalScopeID(e.mapping.MappingID)
	binding := stagedBinding{"momentum", e.mapping.MappingRevision, scopeID, e.mapping.Binding.Account.AccountID, p.server.forest.ID, root.ID}
	scope := p.server.stagedScopes[scopeID]
	if scope == nil {
		scope = &stagedScope{descriptor: stagedDescriptor{Binding: binding, Bounds: p.config.StagedBounds, SourceProfile: personalExistingProfile}}
	}
	if scope.pending != nil || !domainEqual(scope.descriptor.Binding, binding) || scope.descriptor.Bounds != p.config.StagedBounds || scope.descriptor.SourceProfile != personalExistingProfile {
		return nil, nil, sourceDenied()
	}
	if old, present := root.CommandReceipts[stagedScopeKey]; present {
		var actual stagedDescriptor
		if decodeStagedInternal(old, &actual) != nil || !domainEqual(actual, scope.descriptor) {
			return nil, nil, sourceDenied()
		}
	}
	if err = markPreservedSourceClosure(nodes, scope.descriptor); err != nil {
		return nil, nil, err
	}
	revision, err := stagedContentRevision(clone)
	if err != nil {
		return nil, nil, err
	}
	command := stagedCommand{e.mapping.Binding.PrincipalID, binding.AccountID, scopeID, e.key.CommandID, revision, action, digest}
	record := canonicalMutationRecord{NativeCanonicalRevision, action, e.mapping.MappingID, digest}
	raw, err := CanonicalDomainJSON(record)
	if err != nil {
		return nil, nil, err
	}
	receipt := stagedReceipt{Version: 1, Command: command, Fingerprint: stagedCommandFingerprint(binding, command), AfterRevision: revision, Targets: []stagedTarget{}, MappingRecord: raw}
	key := stagedCommandKey(command)
	clone.CommandReceipts[key] = receipt
	if _, err = validateOwnedCandidate(clone, p.config.StagedBounds); err != nil {
		return nil, nil, err
	}
	pending := &stagedPending{root: clone, nodes: nodes, receipt: receipt, key: key}
	scope.pending = pending
	p.server.stagedScopes[scopeID] = scope
	return scope, pending, nil
}
func (p *personalSource) canonicalResult(e *canonicalSourceEntry, action string, r core.PersonalMappingRecord) (json.RawMessage, error) {
	if action == "consent.establish" {
		// Stable native binding/consent identity, not a self-referential whole-file SHA.
		return CanonicalDomainJSON(sourceConsentReceipt{e.key.CommandID, r.ConsentRef, r.ConsentRevision, canonicalAssociationRevision(r), "applied"})
	}
	return CanonicalDomainJSON(canonicalAttachResult{e.key.CommandID, e.mapping.MappingID, r.Binding.BindingRevision, "applied"})
}
func canonicalAssociationRevision(r core.PersonalMappingRecord) string {
	return sourceCommandKey([]interface{}{r.Mapping.Binding, r.ConsentRef, r.ConsentRevision})
}
func (p *personalSource) canonicalHistoryReplayLocked(e *canonicalSourceEntry, h core.PersonalMappingHistory) error {
	var binding stagedBinding
	if sourceDecode(h.Binding, &binding, p.config.Bounds) != nil {
		return sourceUnavailable()
	}
	scope := p.server.stagedScopes[binding.ScopeID]
	root := p.server.forest.Children[binding.RootID]
	if scope == nil || root == nil || scope.pending != nil || !domainEqual(scope.descriptor.Binding, binding) {
		return sourceUnavailable()
	}
	raw, err := json.Marshal(root.CommandReceipts[h.ReceiptKey])
	if err != nil {
		return sourceUnavailable()
	}
	pair, err := stagedReceiptPair(binding, h.ReceiptKey, raw)
	if err != nil {
		return sourceUnavailable()
	}
	p.server.stateWriter.mutex.Lock()
	stamp, err := p.server.stateWriter.pairedStamp(p.server.statePath(), &pair)
	p.server.stateWriter.mutex.Unlock()
	if err != nil {
		return sourceUnavailable()
	}
	e.scope, e.durable, e.result = scope, &stamp, append([]byte(nil), h.Result...)
	return nil
}
func (p *personalSource) canonicalDurableCurrent(e *canonicalSourceEntry) bool {
	if e.durable == nil {
		return false
	}
	p.server.forestMutex.RLock()
	defer p.server.forestMutex.RUnlock()
	root := p.server.forest.Children[e.scope.descriptor.Binding.RootID]
	if root == nil {
		return false
	}
	raw, err := json.Marshal(root.CommandReceipts[e.durable.Pair.Key])
	if err != nil {
		return false
	}
	pair, err := stagedReceiptPair(e.scope.descriptor.Binding, e.durable.Pair.Key, raw)
	return err == nil && pair == e.durable.Pair && domainEqual(p.server.forest.PersonalBindings, e.ledger) || (err == nil && pair == e.durable.Pair && e.ledger == nil)
}
func (p *personalSource) canonicalOverlayLedgerLocked(selected *core.PersonalBindingLedger) (*core.PersonalBindingLedger, error) {
	count := 0
	for _, entry := range p.entries {
		e := entry.canonical
		if e == nil || e.pending == nil || e.scope == nil || e.scope.pending != e.pending || e.ledger == nil {
			continue
		}
		count++
		if count > 1 || !e.write.owns(p.coordinator) {
			return nil, sourceUnavailable()
		}
		selected = e.ledger
	}
	return selected, nil
}
func (p *personalSource) publishCanonicalLocked(scope *stagedScope, pending *stagedPending, stamp stagedDurableStamp) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, source := range p.entries {
		e := source.canonical
		if e == nil || e.scope != scope || e.pending != pending {
			continue
		}
		if e.ledger == nil || !e.write.owns(p.coordinator) || stamp.Pair.Key != pending.key {
			return sourceUnavailable()
		}
		if p.server.forest.Children[pending.root.ID] == nil {
			return sourceDenied()
		}
		p.server.forest.Children[pending.root.ID] = pending.root
		p.server.forest.PersonalBindings = e.ledger
		scope.pending, scope.configured, scope.reconciled = nil, true, true
		return nil
	}
	return sourceUnavailable()
}
func (p *personalSource) recoverCanonicalWitness(ctx context.Context, e *canonicalSourceEntry) error {
	if !e.unknown || e.pending == nil || e.scope == nil || e.write == nil {
		return sourceUnavailable()
	}
	permit, err := p.coordinator.beginWrite(ctx, e.write.key)
	if err != nil {
		return err
	}
	pair, ok := e.prepared.pairs[stagedPairKey(e.scope.descriptor.Binding.ScopeID, e.pending.key)]
	if !ok {
		permit.finish(false, false)
		return sourceUnavailable()
	}
	witness, err := p.server.inspectSourcePair(ctx, e.prepared, pair)
	if err != nil {
		permit.finish(false, false)
		return sourceUnavailable()
	}
	defer witness.close()
	if !permit.owns(p.coordinator) || !witness.current() || ctx.Err() != nil {
		permit.finish(false, false)
		return sourceUnavailable()
	}
	if err = p.server.publishOwnedPair(e.scope.descriptor.Binding.ScopeID, e.pending, witness.stamp); err != nil {
		permit.finish(false, false)
		return sourceUnavailable()
	}
	e.durable = &witness.stamp
	e.pending = nil
	// Factual publication is not authority. Unknown Core cleanup stays pinned.
	if !e.cleanupKnown {
		permit.finish(false, true)
		return sourceUnavailable()
	}
	e.unknown = false
	permit.finish(true, true)
	e.write = nil
	p.releaseCanonicalEntry(e, true)
	return nil
}
func validateCanonicalReceipt(binding stagedBinding, r stagedReceipt, maximum int) error {
	if len(r.MappingRecord) == 0 {
		return nil
	}
	if len(r.ProductIntent)+len(r.EnrollmentRecord) != 0 {
		return sourceInvalid()
	}
	var record canonicalMutationRecord
	bounds := PersonalSourceBounds{MaxRequestBytes: maximum}
	if sourceDecode(r.MappingRecord, &record, bounds) != nil || record.ContractRevision != NativeCanonicalRevision || record.Operation != r.Command.Action || record.StableSHA256 != r.Command.BodySHA256 || canonicalScopeID(record.MappingID) != binding.ScopeID || (record.Operation != "consent.establish" && record.Operation != "mapping.attach") {
		return sourceInvalid()
	}
	return nil
}

func (p *personalSource) validateMappedLedgerLocked(index map[string]*core.Node) error {
	ledger := p.server.forest.PersonalBindings
	if ledger == nil || len(ledger.Mappings) > p.config.Bounds.MaxBindings {
		return sourceUnavailable()
	}
	for id, record := range ledger.Mappings {
		if id != record.Mapping.MappingID || !canonicalMappingValid(record.Mapping, p) || len(record.History) > p.config.StagedBounds.MaxReceipts {
			return sourceUnavailable()
		}
		binding := core.PersonalBindingRecord{OwnerRef: record.Mapping.Binding.OwnerRef, OwnerKind: "existing"}
		if p.actualPersonalRootLocked(binding, index) != nil {
			return sourceUnavailable()
		}
		consent, present := ledger.Consents[record.ConsentRef]
		if !present || consent.Revision != record.ConsentRevision || consent.MappingRef != id || consent.NativeOwnerID != binding.OwnerRef.OwnerID || consent.RootID != binding.OwnerRef.RootID || consent.Issuer != record.Mapping.Issuer || consent.Subject != record.Mapping.Subject {
			return sourceUnavailable()
		}
		if record.Binding != nil && (record.Binding.OwnerRef != binding.OwnerRef || record.Binding.PrincipalID != record.Mapping.Binding.PrincipalID || record.Binding.OwnerKind != "existing" || record.Binding.AssociationID == nil || !existingEnrollmentMatches(record.Binding.Enrollment, *record.Binding.AssociationID)) {
			return sourceUnavailable()
		}
	}
	return nil
}

func (p *personalSource) currentCanonicalControl(e *canonicalSourceEntry) error {
	p.server.forestMutex.RLock()
	defer p.server.forestMutex.RUnlock()
	return p.currentNativeControlLocked(e)
}

func (p *personalSource) controlledSourceClosureLocked(e *canonicalSourceEntry, root *core.Node) (map[string]*core.Node, error) {
	if e.write == nil || !e.write.owns(p.coordinator) || p.currentNativeControlLocked(e) != nil || e.authorityUntil <= domainNow() {
		return nil, sourceDenied()
	}
	nodes, err := stagedForestIndex(root)
	if err != nil || len(nodes) > p.config.StagedBounds.MaxNodes {
		return nil, sourceUnavailable()
	}
	for _, node := range nodes {
		if err = validatePreservedStagedNode(node, p.config.StagedBounds); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}
func markPreservedSourceClosure(nodes map[string]*core.Node, d stagedDescriptor) error {
	for _, node := range nodes {
		if !preservedMarkerMatches(node, d) {
			return sourceDenied()
		}
		if node.CommandReceipts == nil {
			node.CommandReceipts = map[string]interface{}{}
		}
		node.CommandReceipts[stagedScopeKey] = d
	}
	return nil
}

func preservedMarkerMatches(node *core.Node, d stagedDescriptor) bool {
	old, ok := node.CommandReceipts[stagedScopeKey]
	if !ok {
		return true
	}
	var actual stagedDescriptor
	return decodeStagedInternal(old, &actual) == nil && actual == d
}
