// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"io"
	"net/http"
)

func canonicalMappingValid(m CanonicalResolvedMapping, p *personalSource) bool {
	raw, err := CanonicalDomainJSON(m)
	if err != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if DecodeDomainJSON(raw, &fields) != nil {
		return false
	}
	delete(fields, "resolvedMappingSha256")
	if sourceCommandKey(fields) != m.ResolvedMappingSHA256 || m.NativeAuthorityRef != p.config.SourceAuthorityRef || m.SourcePolicyRevision != p.config.SourcePolicyRevision {
		return false
	}
	b := m.Binding
	if b.OwnerRef.RuntimeID != p.server.forest.ID || b.Account.AccountType != "personal" || b.Account.SubjectRef.Kind != "user" || b.Account.AccountID == b.PrincipalID || b.Account.SubjectRef.SubjectID == b.PrincipalID || b.Account.SubjectRef.SubjectID == b.Account.AccountID {
		return false
	}
	return validateStagedIdentifiers(p.config.StagedBounds, m.MappingID, m.MappingRevision, m.ReservationID, m.ReservationRevision, m.Issuer, m.Subject, b.PrincipalID, b.Account.AccountID, b.Account.SubjectRef.SubjectID, b.OwnerRef.RootID, b.OwnerRef.OwnerID) == nil
}
func canonicalConsentDigest(m CanonicalResolvedMapping, command string, expected *string) string {
	return sourceCommandKey(map[string]interface{}{"operation": "identity.association.consent", "mappingId": m.MappingID, "mappingRevision": m.MappingRevision, "resolvedMappingSha256": m.ResolvedMappingSHA256, "issuer": m.Issuer, "subject": m.Subject, "binding": m.Binding, "nativeAuthorityRef": m.NativeAuthorityRef, "sourcePolicyRevision": m.SourcePolicyRevision, "commandId": command, "expectedConsentRevision": expected})
}
func (p *personalSource) mappingCallback(ctx context.Context, e *canonicalSourceEntry, action string, payload interface{}, target interface{}) error {
	runtime := p.server.nativeControl.Load()
	if runtime == nil || p.canonicalEntryCurrent(e) != nil {
		return sourceDenied()
	}
	member, err := CanonicalDomainJSON(payload)
	if err != nil {
		return sourceInvalid()
	}
	c := runtime.config.MappingCallback
	envelope := mappingCallbackEnvelope{CanonicalMappingRevision, c.Issuer, c.Audience, p.config.HostID, p.epoch, e.control.RequestID, action, member}
	body, err := CanonicalDomainJSON(envelope)
	if err != nil || len(body) > p.config.Bounds.MaxRequestBytes {
		return sourceInvalid()
	}
	request, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return sourceUnavailable()
	}
	request.Header.Set("Authorization", "Bearer "+c.ChannelToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := runtime.client.Do(request)
	if err != nil {
		return sourceUnavailable()
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(p.config.Bounds.MaxResponseBytes)+1))
	if err != nil || response.StatusCode != http.StatusOK || len(raw) > p.config.Bounds.MaxResponseBytes {
		return sourceUnavailable()
	}
	bounds := p.config.Bounds
	bounds.MaxRequestBytes = bounds.MaxResponseBytes
	var result mappingCallbackResponse
	if sourceDecode(raw, &result, bounds) != nil || result.ContractRevision != CanonicalMappingRevision || result.Issuer != c.Issuer || result.Audience != c.Audience || result.HostID != p.config.HostID || result.Epoch != p.epoch || result.RequestID != e.control.RequestID || result.Action != action {
		return sourceDenied()
	}
	if sourceDecode(result.Result, target, bounds) != nil || ctx.Err() != nil || p.canonicalEntryCurrent(e) != nil {
		return sourceDenied()
	}
	return nil
}
func (p *personalSource) validCanonicalResult(e *canonicalSourceEntry, v verifiedCanonicalMapping, stage string) bool {
	if v.ContractRevision != CanonicalMappingRevision || v.Stage != stage || !domainEqual(v.Mapping, e.mapping) || !domainEqual(v.Subject, e.subject) || v.RequestID != e.control.RequestID || v.RawRequestSHA256 != e.key.RawRequestSHA256 || v.StableCommandSHA256 != e.key.StableCommandSHA256 {
		return false
	}
	purpose := "identity.association.consent"
	if stage == "current" {
		purpose = "identity.mapping.current"
	}
	if v.Purpose != purpose || !validNativeTimes(v.CheckedAt, v.ValidUntil, domainNow(), p.config.Bounds.LeaseSeconds) || v.ValidUntil > e.control.ValidUntil {
		return false
	}
	if stage == "current" {
		return canonicalCurrentStateMatches(v.Canonical, e.mapping)
	}
	return true
}
func canonicalCurrentStateMatches(c CanonicalState, m CanonicalResolvedMapping) bool {
	g := c.PersonalGrant
	return c.PrincipalRegistered && c.AccountRegistryRevision != nil && *c.AccountRegistryRevision != "" && g != nil && g.PrincipalID == m.Binding.PrincipalID && g.State == "active" && g.Revision != "" && domainEqual(g.Account, m.Binding.Account) && g.Scope.AccountID == m.Binding.Account.AccountID && g.Scope.Product == "momentum" && domainContains(g.Capabilities, "identity.read")
}
func (p *personalSource) establishCanonicalConsent(ctx context.Context, r SourceEnvelope) (interface{}, error) {
	var i canonicalConsentInput
	if sourceDecode(r.Payload, &i, p.config.Bounds) != nil || !canonicalMappingValid(i.ResolvedMapping, p) {
		return nil, sourceInvalid()
	}
	captured, err := p.capturedControl(i.ControlRef)
	if err != nil || i.RootID != captured.facts.rootID || i.OwnerID != captured.held.ownerID || i.ResolvedMapping.Binding.OwnerRef.RootID != i.RootID || i.ResolvedMapping.Binding.OwnerRef.OwnerID != i.OwnerID || i.SupabaseEvidence.Issuer != i.ResolvedMapping.Issuer || i.SupabaseEvidence.Subject != i.ResolvedMapping.Subject {
		return nil, sourceDenied()
	}
	key := MappingCheckKey{i.CommandID, r.RequestID, stagedHash(r.Payload), canonicalConsentDigest(i.ResolvedMapping, i.CommandID, i.ExpectedConsentRevision), i.ExpectedConsentRevision, "open"}
	writer, err := p.coordinator.beginWrite(ctx, canonicalWriterKey(i.ResolvedMapping, i.CommandID, "consent.establish"))
	if err != nil {
		return nil, err
	}
	e, err := p.registerControlEntry(r, i.SupabaseEvidence, captured, key, writer)
	if err != nil {
		writer.noEffect(true)
		return nil, err
	}
	e.mapping = i.ResolvedMapping
	e.cleanupKnown = false
	result, err := p.runCanonicalConsent(ctx, e, i.CanonicalMappingRef)
	if err != nil {
		p.failCanonicalOperation(ctx, e)
		return nil, err
	}
	return result, nil
}
func (p *personalSource) runCanonicalConsent(ctx context.Context, e *canonicalSourceEntry, reference string) (interface{}, error) {
	snapshot, err := p.buildControlSnapshot(e, "identity.association.consent", "open")
	if err != nil {
		return nil, err
	}
	var guard mappingGuard
	payload := map[string]interface{}{"canonicalMappingRef": reference, "nativeControlSnapshot": snapshot, "subject": e.subject, "commandId": e.key.CommandID, "expectedConsentRevision": e.key.ExpectedRevision, "rawRequestSha256": e.key.RawRequestSHA256, "stableCommandSha256": e.key.StableCommandSHA256}
	if err = p.mappingCallback(ctx, e, "mapping.open", payload, &guard); err != nil {
		return nil, err
	}
	if !p.validCanonicalResult(e, guard.Mapping, "prepared") || !p.validMappingGuard(e, guard.Reference) {
		return nil, sourceDenied()
	}
	e.guard = &guard.Reference
	e.authorityUntil = min(guard.Reference.ValidUntil, guard.Mapping.ValidUntil)
	if _, err = p.checkCanonicalPhase(ctx, e, "effect"); err != nil {
		return nil, err
	}
	if err = p.persistCanonical(ctx, e, "consent.establish", guard.Mapping.Canonical, nil); err != nil {
		return nil, err
	}
	if _, err = p.checkCanonicalPhase(ctx, e, "disclosure"); err != nil {
		return nil, err
	}
	if err = p.releaseCanonicalGuard(ctx, e, "complete"); err != nil {
		return nil, err
	}
	if err = p.finishCanonicalKnown(e); err != nil {
		return nil, err
	}
	var receipt sourceConsentReceipt
	if sourceDecode(e.result, &receipt, p.config.Bounds) != nil {
		return nil, sourceUnavailable()
	}
	return receipt, nil
}
func (p *personalSource) validMappingGuard(e *canonicalSourceEntry, g mappingGuardRef) bool {
	return g.GuardRef != "" && g.HostID == p.config.HostID && g.Epoch == p.epoch && g.RequestID == e.control.RequestID && g.CommandID == e.key.CommandID && g.RawRequestSHA256 == e.key.RawRequestSHA256 && g.StableCommandSHA256 == e.key.StableCommandSHA256 && g.ValidUntil <= e.control.ValidUntil && g.ValidUntil > domainNow()
}
func (p *personalSource) checkCanonicalPhase(ctx context.Context, e *canonicalSourceEntry, phase string) (verifiedCanonicalMapping, error) {
	snapshot, err := p.buildControlSnapshot(e, "identity.association.consent", phase)
	if err != nil {
		return verifiedCanonicalMapping{}, err
	}
	var result verifiedCanonicalMapping
	payload := map[string]interface{}{"guardRef": e.guard, "phase": phase, "nativeControlSnapshot": snapshot, "rawRequestSha256": e.key.RawRequestSHA256, "stableCommandSha256": e.key.StableCommandSHA256}
	if err = p.mappingCallback(ctx, e, "mapping.check", payload, &result); err != nil || !p.validCanonicalResult(e, result, "prepared") {
		return result, sourceDenied()
	}
	e.authorityUntil = min(e.authorityUntil, result.ValidUntil)
	return result, nil
}
func (p *personalSource) releaseCanonicalGuard(ctx context.Context, e *canonicalSourceEntry, mode string) error {
	var snapshot *NativeControlSnapshot
	if mode == "complete" {
		value, err := p.buildControlSnapshot(e, "identity.association.consent", "complete")
		if err != nil {
			return err
		}
		snapshot = &value
	}
	var ack mappingReleaseAck
	payload := map[string]interface{}{"guardRef": e.guard, "mode": mode, "nativeControlSnapshot": snapshot}
	if err := p.mappingCallback(ctx, e, "mapping.release", payload, &ack); err != nil {
		return err
	}
	if e.guard == nil || ack.GuardRef != e.guard.GuardRef || ack.CheckedAt > domainNow() {
		return sourceDenied()
	}
	if mode == "complete" && (ack.State != "completed" || ack.Transaction != "committed" || ack.Current == nil || ack.ValidUntil == nil || !p.validCanonicalResult(e, *ack.Current, "prepared") || *ack.ValidUntil <= domainNow()) {
		return sourceDenied()
	}
	if mode == "cancel" && (ack.State != "cancelled" || ack.Transaction != "rolled_back" || ack.Current != nil || ack.ValidUntil != nil) {
		return sourceDenied()
	}
	e.cleanupKnown = true
	return nil
}
func (p *personalSource) attachCanonicalMapping(ctx context.Context, r SourceEnvelope) (interface{}, error) {
	var i canonicalAttachInput
	if sourceDecode(r.Payload, &i, p.config.Bounds) != nil || !existingEnrollmentMatches(i.EnrollmentRef, i.Record.AssociationID) || validateSourceSubject(i.Subject, r.RequestID, p.config.Bounds) != nil {
		return nil, sourceDenied()
	}
	record, captured, err := p.attachSourceRecord(i)
	if err != nil {
		return nil, err
	}
	writer, err := p.coordinator.beginWrite(ctx, canonicalWriterKey(record.Mapping, i.CommandID, "mapping.attach"))
	if err != nil {
		return nil, err
	}
	expected := record.ConsentRevision
	key := MappingCheckKey{i.CommandID, r.RequestID, stagedHash(r.Payload), canonicalConsentDigest(record.Mapping, i.CommandID, &expected), &expected, "current"}
	e, err := p.registerControlEntry(r, i.Subject, captured, key, writer)
	if err != nil {
		writer.noEffect(true)
		return nil, err
	}
	e.mapping, e.association, e.enrollment = record.Mapping, &i.Record, &i.EnrollmentRef
	e.cleanupKnown = false
	seal, err := p.currentConsent(e, "identity.association.enroll", i.Record.AssociationID, i.EnrollmentRef)
	if err != nil {
		p.failCanonicalOperation(ctx, e)
		return nil, err
	}
	var verified verifiedCanonicalMapping
	payload := map[string]interface{}{"canonicalMappingRef": i.CanonicalMappingRef, "subject": i.Subject, "associationId": i.Record.AssociationID, "enrollmentRef": i.EnrollmentRef, "currentNativeConsent": seal, "rawRequestSha256": e.originalSHA}
	err = p.mappingCallback(ctx, e, "mapping.verifyCurrent", payload, &verified)
	if err != nil || !p.validCanonicalResult(e, verified, "current") {
		p.failCanonicalOperation(ctx, e)
		return nil, sourceDenied()
	}
	e.authorityUntil = verified.ValidUntil
	e.cleanupKnown = true // Current worker returned only after SQL and real credential disposal.
	err = p.persistCanonical(ctx, e, "mapping.attach", verified.Canonical, i.ExpectedBindingRevision)
	if err != nil {
		p.failCanonicalOperation(ctx, e)
		return nil, err
	}
	if err = p.finishCanonicalKnown(e); err != nil {
		return nil, err
	}
	var result canonicalAttachResult
	if sourceDecode(e.result, &result, p.config.Bounds) != nil {
		return nil, sourceUnavailable()
	}
	return result, nil
}
func (p *personalSource) attachSourceRecord(i canonicalAttachInput) (core.PersonalMappingRecord, *canonicalSourceEntry, error) {
	p.server.forestMutex.RLock()
	ledger := p.server.forest.PersonalBindings
	var selected core.PersonalMappingRecord
	count := 0
	if ledger == nil {
		p.server.forestMutex.RUnlock()
		return selected, nil, sourceDenied()
	}
	for _, m := range ledger.Mappings {
		if m.ConsentRef != i.Record.ConsentRef || !domainEqual(m.Mapping.Binding, i.Record.Binding) || m.Mapping.Issuer != i.Subject.Issuer || m.Mapping.Subject != i.Subject.Subject {
			continue
		}
		selected = m
		count++
	}
	p.server.forestMutex.RUnlock()
	if count != 1 {
		return selected, nil, sourceDenied()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var captured *canonicalSourceEntry
	for _, source := range p.entries {
		e := source.canonical
		if e == nil || e.control.LeaseID != "" || e.facts.rootID != selected.Mapping.Binding.OwnerRef.RootID || e.held.ownerID != selected.Mapping.Binding.OwnerRef.OwnerID || e.closing || e.unknown || e.held.ref.ValidUntil <= domainNow() {
			continue
		}
		if captured != nil {
			return selected, nil, sourceDenied()
		}
		captured = e
	}
	if captured == nil {
		return selected, nil, sourceDenied()
	}
	return selected, captured, nil
}
func (p *personalSource) failCanonicalOperation(ctx context.Context, e *canonicalSourceEntry) {
	if e.guard != nil && e.pending == nil && p.releaseCanonicalGuard(ctx, e, "cancel") == nil {
		e.cleanupKnown = true
	}
	if e.guard == nil && !e.cleanupKnown {
		e.unknown = true
	}
	if e.pending != nil || !e.cleanupKnown {
		e.unknown = true
		if e.write != nil {
			e.write.finish(false, e.pending != nil)
		}
		return
	}
	e.write.noEffect(true)
	p.releaseCanonicalEntry(e, true)
}
func canonicalWriterKey(m CanonicalResolvedMapping, command, action string) string {
	return sourceCommandKey([]interface{}{m.MappingID, m.Binding, command, action})
}
func (p *personalSource) finishCanonicalKnown(e *canonicalSourceEntry) error {
	if !e.cleanupKnown || p.canonicalEntryCurrent(e) != nil || e.durable == nil {
		return sourceUnavailable()
	}
	if !p.canonicalDurableCurrent(e) {
		return sourceUnavailable()
	}
	e.write.finish(true, true)
	e.write = nil
	p.releaseCanonicalEntry(e, true)
	return nil
}

func (p *personalSource) dispatchCanonical(ctx context.Context, r SourceEnvelope) (interface{}, error) {
	switch r.Action {
	case "control.capture":
		return p.captureNativeControl(r)
	case "control.open":
		return p.openNativeControl(r)
	case "control.recheck":
		return p.recheckNativeControl(r)
	case "control.release":
		return p.releaseNativeControl(r)
	case "consent.establish":
		return p.establishCanonicalConsent(ctx, r)
	case "mapping.attach":
		return p.attachCanonicalMapping(ctx, r)
	case "mapping.currentSeal":
		return p.emitCurrentSeal(r)
	case "identity.openPrecanonical":
		return p.openPrecanonicalIdentity(r)
	case "subjectRoots.snapshot":
		return p.subjectRoots(r, false)
	case "subjectRoots.state":
		return p.subjectRootsState(r, false)
	case "subjectRoots.recheck":
		return p.subjectRootsState(r, true)
	case "subjectRoots.close":
		return p.subjectRootsClose(ctx, r)
	case "identity.open":
		return p.identityOpen(r, false)
	case "identity.openCurrent":
		return p.identityOpen(r, true)
	case "identity.recheck":
		return p.identityRecheck(r)
	case "binding.open":
		return p.bindingOpen(r)
	case "binding.recheck":
		return p.bindingRecheck(r)
	case "context.resolve":
		return p.resolveContext(r)
	case "resources.open":
		return p.resourcesOpen(r)
	case "resources.recheck":
		return p.resourcesRecheck(r)
	case "lease.recheck":
		return p.leaseRecheck(r)
	case "lease.release":
		return p.leaseRelease(ctx, r)
	}
	return nil, sourceInvalid()
}
