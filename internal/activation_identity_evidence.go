// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"github.com/NeoTecDigital/LumberJack/core"
	"time"
)

type sourceIdentityOpen struct {
	NativeEvidenceRef string                `json:"nativeEvidenceRef"`
	Subject           SourceSubjectEvidence `json:"subject"`
	Purpose           string                `json:"purpose"`
}
type sourceIdentityCurrent struct {
	Record  SourceAssociationRecord `json:"record"`
	Subject SourceSubjectEvidence   `json:"subject"`
	Purpose string                  `json:"purpose"`
}
type sourceIdentityRecheck struct {
	LeaseRef SourceLeaseRef        `json:"leaseRef"`
	Subject  SourceSubjectEvidence `json:"subject"`
	Purpose  string                `json:"purpose"`
}
type sourceIdentityResult struct {
	LeaseRef SourceLeaseRef            `json:"leaseRef"`
	Evidence NativeAssociationEvidence `json:"evidence"`
}

func (p *personalSource) identityInput(request SourceEnvelope, current bool) (SourceSubjectEvidence, *SourceAssociationRecord, string, string, error) {
	if current {
		var input sourceIdentityCurrent
		if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
			return SourceSubjectEvidence{}, nil, "", "", sourceInvalid()
		}
		if input.Purpose != "identity.association.resolve" && input.Purpose != "identity.association.enroll" {
			return SourceSubjectEvidence{}, nil, "", "", sourceDenied()
		}
		return input.Subject, &input.Record, input.Purpose, input.Record.ConsentRef, nil
	}
	var input sourceIdentityOpen
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return SourceSubjectEvidence{}, nil, "", "", sourceInvalid()
	}
	if input.Purpose != "identity.association.establish" {
		return SourceSubjectEvidence{}, nil, "", "", sourceDenied()
	}
	return input.Subject, nil, input.Purpose, input.NativeEvidenceRef, nil
}
func (p *personalSource) identityOpen(request SourceEnvelope, current bool) (interface{}, error) {
	subject, record, purpose, consentRef, err := p.identityInput(request, current)
	if err != nil {
		return nil, err
	}
	if err = validateSourceSubject(subject, request.RequestID, p.config.Bounds); err != nil {
		return nil, err
	}
	entry, err := p.newReadEntry(request, consentRef, request.Payload, subject.ValidUntil, nil)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	entry.subject, entry.record, entry.purpose, entry.consentRef = subject, record, purpose, consentRef
	p.mu.Unlock()
	p.server.forestMutex.RLock()
	evidence, err := p.identityEvidenceLocked(entry, consentRef)
	p.server.forestMutex.RUnlock()
	if err != nil {
		p.closeReadEntry(entry)
		return nil, err
	}
	if err = p.registerIdentityEntry(entry, subject, evidence); err != nil {
		p.closeReadEntry(entry)
		return nil, err
	}
	return sourceIdentityResult{entry.ref, evidence}, nil
}
func (p *personalSource) registerIdentityEntry(entry *personalSourceEntry, subject SourceSubjectEvidence, evidence NativeAssociationEvidence) error {
	key := enrollmentSessionKey{evidence.Binding.PrincipalID, subject.SessionID}
	admission, err := p.coordinator.reserveSession(key, p.config.Bounds.MaxLeases)
	if err != nil {
		return err
	}
	defer admission.release()
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry.closed || entry.ref.ValidUntil <= domainNow() {
		return sourceDenied()
	}
	entry.ref.ConsentRevision = &evidence.ConsentRevision
	entry.ref.OwnerRootBindingSHA256 = sourceCommandKey(evidence.Binding)
	entry.actor = SourceActor{evidence.Binding.PrincipalID, "human", subject.SessionID, subject}
	entry.grant.Scope = SourceScope{evidence.Binding.Account.AccountID, "momentum"}
	entry.owner = evidence.Binding.OwnerRef
	return nil
}
func (p *personalSource) identityEvidenceLocked(entry *personalSourceEntry, consentRef string) (NativeAssociationEvidence, error) {
	if entry.canonicalFamily {
		return p.mappedIdentityEvidenceLocked(entry, consentRef)
	}
	ledger := p.server.forest.PersonalBindings
	if ledger == nil || entry.read.recheck() != nil {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	consent, present := ledger.Consents[consentRef]
	subject := entry.subject
	if !present || consent.State != "active" || consent.Issuer != subject.Issuer || consent.Subject != subject.Subject || consent.MappingRef == "" {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	binding, err := uniqueConsentBinding(ledger, consentRef)
	if err != nil {
		return NativeAssociationEvidence{}, err
	}
	index, err := stagedForestIndex(p.server.forest)
	if err != nil || p.actualPersonalRootLocked(binding, index) != nil || consent.NativeOwnerID != binding.OwnerRef.OwnerID || consent.RootID != binding.OwnerRef.RootID {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	native := SourceNativeBinding{binding.PrincipalID, binding.Account, binding.OwnerRef}
	revision := sourceCommandKey([]interface{}{native, consent})
	if entry.record != nil && !currentAssociationMatches(*entry.record, binding, consent, revision, p.config) {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	until := min(entry.ref.ValidUntil, subject.ValidUntil)
	if until <= domainNow() {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	return NativeAssociationEvidence{native, p.config.SourceAuthorityRef, subject.Issuer, subject.Subject, subject.SessionID, consent.NativeOwnerID, entry.ref.RequestID, entry.purpose, revision, p.config.SourcePolicyRevision, consent.ConsentRef, consent.Revision, domainNow(), until}, nil
}
func uniqueConsentBinding(ledger *core.PersonalBindingLedger, ref string) (core.PersonalBindingRecord, error) {
	var selected core.PersonalBindingRecord
	count := 0
	for _, binding := range ledger.Bindings {
		if binding.ConsentRef != nil && *binding.ConsentRef == ref {
			selected = binding
			count++
		}
	}
	if count != 1 {
		return selected, sourceDenied()
	}
	return selected, nil
}
func currentAssociationMatches(record SourceAssociationRecord, binding core.PersonalBindingRecord, consent core.PersonalConsentRecord, revision string, config PersonalSourceConfig) bool {
	if binding.AssociationID == nil || binding.AssociationRevision == nil {
		return false
	}
	return record.AssociationID == *binding.AssociationID && record.Revision == *binding.AssociationRevision && record.State == "active" && record.Issuer == consent.Issuer && record.Subject == consent.Subject && domainEqual(record.Binding, SourceNativeBinding{binding.PrincipalID, binding.Account, binding.OwnerRef}) && record.NativeAuthorityRef == config.SourceAuthorityRef && record.SourcePolicyRevision == config.SourcePolicyRevision && record.SourceRevision == revision && record.ConsentRef == consent.ConsentRef && record.ConsentRevision == consent.Revision
}
func (p *personalSource) identityRecheck(request SourceEnvelope) (interface{}, error) {
	var input sourceIdentityRecheck
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	entry, err := p.lookupEntry(input.LeaseRef, request.RequestID)
	if err != nil || entry.purpose != input.Purpose || !sourceSubjectSame(entry.subject, input.Subject) || entry.ref.ConsentRevision == nil {
		return nil, sourceDenied()
	}
	if validateSourceSubject(input.Subject, request.RequestID, p.config.Bounds) != nil {
		return nil, sourceDenied()
	}
	p.server.forestMutex.RLock()
	ref := ""
	if entry.record != nil {
		ref = entry.record.ConsentRef
	}
	if ref == "" {
		ref = entry.consentRef
	}
	local := *entry
	local.subject = input.Subject
	evidence, err := p.identityEvidenceLocked(&local, ref)
	p.server.forestMutex.RUnlock()
	if err != nil {
		return nil, err
	}
	return evidence, nil
}
func (p *personalSource) closeReadEntry(entry *personalSourceEntry) {
	p.mu.Lock()
	if entry.canonical != nil {
		entry.canonical.closing = true
		if entry.canonical.source == nil {
			p.mu.Unlock()
			return
		}
	}
	if entry.closed || entry.unknown || (entry.provision != nil && !entry.guard) {
		p.mu.Unlock()
		return
	}
	entry.closed = true
	delete(p.entries, entry.ref.LeaseID)
	complete := p.onComplete
	p.mu.Unlock()
	if entry.read != nil {
		entry.read.release()
	}
	if complete != nil {
		complete(entry.ref.LeaseID)
	}
}

// Mapped EXISTING data uses durable genuine native ownership/consent and current
// protected Core actor checks. An old native JWT/session is NOT a second login.
func (p *personalSource) mappedBindingLocked(entry *personalSourceEntry) (core.PersonalBindingRecord, bool) {
	ledger := p.server.forest.PersonalBindings
	if ledger == nil || entry.intent == nil {
		return core.PersonalBindingRecord{}, false
	}
	var selected core.PersonalBindingRecord
	count := 0
	for _, record := range ledger.Mappings {
		b := record.Binding
		if b != nil && b.PrincipalID == entry.actor.PrincipalID && domainEqual(b.Account, entry.grant.Account) && b.OwnerRef == entry.intent.OwnerRef && b.BindingRevision == entry.intent.BindingRevision && record.Mapping.Issuer == entry.actor.Evidence.Issuer && record.Mapping.Subject == entry.actor.Evidence.Subject {
			selected = *b
			count++
		}
	}
	if count == 0 {
		return exactPrimaryNewBinding(ledger, entry)
	}
	if count != 1 || !p.mappedOwnerProfileCurrentLocked(selected.OwnerRef.OwnerID) {
		return selected, false
	}
	return selected, true
}
func (p *personalSource) mappedOwnerProfileCurrentLocked(owner string) bool {
	profile, err := p.server.forest.GetUserProfile(owner)
	return err == nil && profile.LockedUntil <= time.Now().Unix()
}
func (p *personalSource) mappedIdentityEvidenceLocked(entry *personalSourceEntry, ref string) (NativeAssociationEvidence, error) {
	if entry.read == nil || entry.read.recheck() != nil {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	ledger := p.server.forest.PersonalBindings
	if ledger == nil {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	var selected core.PersonalMappingRecord
	count := 0
	for _, record := range ledger.Mappings {
		if record.ConsentRef == ref && record.Mapping.Issuer == entry.subject.Issuer && record.Mapping.Subject == entry.subject.Subject && record.Binding != nil {
			selected = record
			count++
		}
	}
	if count != 1 || !p.mappedOwnerProfileCurrentLocked(selected.Mapping.Binding.OwnerRef.OwnerID) {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	consent, ok := ledger.Consents[ref]
	if !ok || consent.State != "active" || consent.Revision != selected.ConsentRevision {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	if entry.record != nil && !canonicalAssociationMatches(*entry.record, selected, consent, p.config) {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	index, err := stagedForestIndex(p.server.forest)
	if err != nil || p.actualPersonalRootLocked(*selected.Binding, index) != nil {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	native := selected.Mapping.Binding
	return NativeAssociationEvidence{SourceNativeBinding{native.PrincipalID, native.Account, native.OwnerRef}, p.config.SourceAuthorityRef, entry.subject.Issuer, entry.subject.Subject, entry.subject.SessionID, native.OwnerRef.OwnerID, entry.ref.RequestID, entry.purpose, canonicalAssociationRevision(selected), p.config.SourcePolicyRevision, ref, consent.Revision, domainNow(), min(entry.ref.ValidUntil, entry.subject.ValidUntil)}, nil
}
func canonicalAssociationMatches(a SourceAssociationRecord, r core.PersonalMappingRecord, c core.PersonalConsentRecord, p PersonalSourceConfig) bool {
	return a.State == "active" && a.Issuer == r.Mapping.Issuer && a.Subject == r.Mapping.Subject && domainEqual(a.Binding, r.Mapping.Binding) && a.NativeAuthorityRef == p.SourceAuthorityRef && a.SourcePolicyRevision == p.SourcePolicyRevision && a.ConsentRef == c.ConsentRef && a.ConsentRevision == c.Revision && a.SourceRevision == canonicalAssociationRevision(r)
}

// Independent exact primary NEW selection, never a failed-EXISTING fallback.
func exactPrimaryNewBinding(l *core.PersonalBindingLedger, e *personalSourceEntry) (core.PersonalBindingRecord, bool) {
	b, ok := l.Bindings[e.grant.Account.AccountID]
	if !ok || b.OwnerKind != "new" || b.PrincipalID != e.actor.PrincipalID || !domainEqual(b.Account, e.grant.Account) || b.OwnerRef != e.intent.OwnerRef || b.BindingRevision != e.intent.BindingRevision {
		return b, false
	}
	for _, r := range l.Mappings {
		if r.Binding != nil && r.Binding.OwnerRef == b.OwnerRef {
			return b, false
		}
	}
	return b, true
}
