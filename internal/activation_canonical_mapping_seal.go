// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/core"
	"strings"
)

func (p *personalSource) nativeSourceIdentity() nativeSourceIdentity {
	return nativeSourceIdentity{p.config.SourceAuthorityRef, p.server.forest.ID, p.config.HostID, p.epoch, p.config.SourcePolicyRevision}
}
func unsignedNativeSnapshot(snapshot interface{}) (json.RawMessage, error) {
	raw, err := CanonicalDomainJSON(snapshot)
	if err != nil {
		return nil, sourceInvalid()
	}
	var shape map[string]json.RawMessage
	if DecodeDomainJSON(raw, &shape) != nil {
		return nil, sourceInvalid()
	}
	delete(shape, "sealRef")
	return CanonicalDomainJSON(shape)
}
func (p *personalSource) signNativeSnapshot(e *canonicalSourceEntry, snapshot interface{}, association *string, enrollment *SourceEnrollment) (string, error) {
	runtime := p.server.nativeControl.Load()
	if runtime == nil || p.canonicalEntryCurrent(e) != nil {
		return "", sourceDenied()
	}
	raw, err := unsignedNativeSnapshot(snapshot)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return "", sourceUnavailable()
	}
	id := base64.RawURLEncoding.EncodeToString(nonce)
	permit := "read"
	prefix := "s1r."
	if e.write != nil {
		permit, prefix = "writer", "s1w."
	}
	body := nativeSignedSeal{NativeCanonicalRevision, runtime.config.Seal.KeyID, id, permit, p.nativeSourceIdentity(), raw, association, enrollment}
	bytes, err := CanonicalDomainJSON(body)
	if err != nil || len(bytes) > p.config.Bounds.MaxResponseBytes {
		return "", sourceUnavailable()
	}
	token := prefix + id + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(runtime.privateKey, bytes))
	p.mu.Lock()
	defer p.mu.Unlock()
	if e.closing || e.unknown || len(e.seals) >= p.config.Bounds.MaxFields {
		return "", sourceUnavailable()
	}
	e.seals[id] = stagedHash(bytes)
	return token, nil
}

// No handle, registry, clock lookup, I/O, callback or lock. Actual backend clock
// and preloaded trust are explicit; signature never grants current graph rights.
func VerifyNativeSourceSeal(raw []byte) ([]byte, error) {
	var initial map[string]json.RawMessage
	var policy nativeVerifyPolicy
	if DecodeDomainJSON(raw, &initial) != nil || DecodeDomainJSON(initial["policy"], &policy) != nil {
		return nil, sourceInvalid()
	}
	if !validNativeVerifyPolicy(policy) {
		return nil, sourceInvalid()
	}
	var input nativeVerifyInput
	if sourceDecode(raw, &input, policy.Bounds) != nil || !domainEqual(input.Policy, policy) {
		return nil, sourceInvalid()
	}
	unsigned, token, permit, err := validateNativeSealSnapshot(input)
	if err != nil {
		return nil, err
	}
	id, signature, err := splitNativeSeal(token, permit)
	if err != nil {
		return nil, err
	}
	body := nativeSignedSeal{NativeCanonicalRevision, policy.KeyID, id, permit, policy.SourceIdentity, unsigned, input.Expected.AssociationID, input.Expected.EnrollmentRef}
	data, err := CanonicalDomainJSON(body)
	if err != nil || !ed25519.Verify(policy.PublicKey, data, signature) {
		return nil, sourceDenied()
	}
	return append([]byte(nil), input.Snapshot...), nil
}
func validNativeVerifyPolicy(p nativeVerifyPolicy) bool {
	if p.ContractRevision != NativeCanonicalRevision || len(p.PublicKey) != 32 || p.KeyID == "" || p.Bounds.MaxRequestBytes <= 0 || p.Bounds.MaxResponseBytes <= 0 || !validNativePolicyBounds(p.Bounds) {
		return false
	}
	raw, err := CanonicalDomainJSON(p.Bounds)
	var checked PersonalSourceBounds
	return err == nil && sourceDecode(raw, &checked, p.Bounds) == nil && domainEqual(checked, p.Bounds) && p.SourceIdentity.NativeAuthorityRef != "" && p.SourceIdentity.RuntimeID != "" && p.SourceIdentity.HostID != "" && p.SourceIdentity.Epoch != "" && p.SourceIdentity.SourcePolicyRevision != ""
}
func splitNativeSeal(token, permit string) (string, []byte, error) {
	parts := strings.Split(token, ".")
	prefix := "s1r"
	if permit == "writer" {
		prefix = "s1w"
	}
	if len(parts) != 3 || parts[0] != prefix {
		return "", nil, sourceDenied()
	}
	nonce, e1 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, e2 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || len(nonce) != 16 || len(signature) != 64 || base64.RawURLEncoding.EncodeToString(nonce) != parts[1] || base64.RawURLEncoding.EncodeToString(signature) != parts[2] {
		return "", nil, sourceDenied()
	}
	return parts[1], signature, nil
}
func validateNativeSealSnapshot(input nativeVerifyInput) (json.RawMessage, string, string, error) {
	e := input.Expected
	if !validNativeExpected(e, input.Policy.Bounds) {
		return nil, "", "", sourceDenied()
	}
	switch e.Kind {
	case "nativeControlSnapshot":
		return validateNativeControlSeal(input)
	case "currentNativeConsent":
		return validateCurrentNativeSeal(input)
	case "precanonicalAssociationEvidence":
		return validatePrecanonicalSeal(input)
	}
	return nil, "", "", sourceInvalid()
}
func validNativeExpected(e nativeVerifyExpected, b PersonalSourceBounds) bool {
	s, k := e.Subject, e.CheckKey
	if !domainFinite(e.Now) || e.Now <= 0 || e.RequestID != s.RequestID || e.RequestID != k.RequestID || !domainValidHash(k.RawRequestSHA256) || !domainValidHash(k.StableCommandSHA256) {
		return false
	}
	return s.Issuer != "" && s.Subject != "" && s.Audience != "" && s.SessionID != "" && (s.Assurance == "aal1" || s.Assurance == "aal2") && validNativeTimes(s.CheckedAt, s.ValidUntil, e.Now, b.LeaseSeconds)
}
func validNativeTimes(checked, until, now, ttl float64) bool {
	return domainFinite(checked) && domainFinite(until) && checked >= 0 && checked <= now && now < until && now-checked <= ttl && until-now <= ttl
}
func validateNativeControlSeal(i nativeVerifyInput) (json.RawMessage, string, string, error) {
	var s NativeControlSnapshot
	if sourceDecode(i.Snapshot, &s, i.Policy.Bounds) != nil {
		return nil, "", "", sourceInvalid()
	}
	e := i.Expected
	permit := "read"
	if e.Purpose == "identity.association.consent" && domainContains([]string{"open", "effect", "disclosure", "complete"}, e.CheckKey.Phase) {
		permit = "writer"
	} else if e.Purpose != "identity.mapping.prepare" || e.CheckKey.Phase != "prepare" {
		return nil, "", "", sourceDenied()
	}
	if e.AssociationID != nil || e.EnrollmentRef != nil || !nativeControlSnapshotMatches(i, s) {
		return nil, "", "", sourceDenied()
	}
	raw, err := unsignedNativeSnapshot(s)
	return raw, s.SealRef, permit, err
}
func nativeControlSnapshotMatches(i nativeVerifyInput, s NativeControlSnapshot) bool {
	e := i.Expected
	identity := i.Policy.SourceIdentity
	actual := nativeSourceIdentity{s.Source.NativeAuthorityRef, s.Source.RuntimeID, s.Source.HostID, s.Source.Epoch, s.Source.SourcePolicyRevision}
	if !domainEqual(actual, identity) || !domainValidHash(s.Source.SourceRevision) || !domainValidHash(s.Root.RootRevision) || !domainValidHash(s.Root.LineageRevision) || s.Root.OwnerID != s.Root.CreatedBy || s.Root.OwnerID != s.Control.NativeProfileRef {
		return false
	}
	if !canonicalNativeEpoch(s.Control.NativeCredentialEpoch) || s.RequestID != e.RequestID || s.Purpose != e.Purpose || !domainEqual(s.CheckKey, e.CheckKey) || !domainEqual(s.Subject, e.Subject) {
		return false
	}
	return validNativeTimes(s.CheckedAt, s.ValidUntil, e.Now, i.Policy.Bounds.LeaseSeconds) && s.ValidUntil <= e.Subject.ValidUntil
}
func validateCurrentNativeSeal(i nativeVerifyInput) (json.RawMessage, string, string, error) {
	var s CurrentNativeConsent
	if sourceDecode(i.Snapshot, &s, i.Policy.Bounds) != nil {
		return nil, "", "", sourceInvalid()
	}
	e := i.Expected
	if e.AssociationID == nil || e.EnrollmentRef == nil || !existingEnrollmentMatches(*e.EnrollmentRef, *e.AssociationID) || !nativeAssociationSealMatches(i, s.Evidence, s.CheckKey) {
		return nil, "", "", sourceDenied()
	}
	if e.Purpose != "identity.association.resolve" && e.Purpose != "identity.association.enroll" {
		return nil, "", "", sourceDenied()
	}
	permit := "read"
	if strings.HasPrefix(s.SealRef, "s1w.") {
		permit = "writer"
	}
	raw, err := unsignedNativeSnapshot(s)
	return raw, s.SealRef, permit, err
}
func nativeAssociationSealMatches(i nativeVerifyInput, p NativeAssociationEvidence, k MappingCheckKey) bool {
	e := i.Expected
	if e.CheckKey.Phase != "current" || !domainEqual(k, e.CheckKey) || p.Purpose != e.Purpose || p.RequestID != e.RequestID || p.ActorIssuer != e.Subject.Issuer || p.ActorSubject != e.Subject.Subject || p.ActorSessionID != e.Subject.SessionID {
		return false
	}
	if p.NativeAuthorityRef != i.Policy.SourceIdentity.NativeAuthorityRef || p.SourcePolicyRevision != i.Policy.SourceIdentity.SourcePolicyRevision || p.NativeActorOwnerID != p.Binding.OwnerRef.OwnerID || p.Binding.OwnerRef.RuntimeID != i.Policy.SourceIdentity.RuntimeID || p.Binding.Account.AccountType != "personal" || p.Binding.Account.SubjectRef.Kind != "user" {
		return false
	}
	return validNativeTimes(p.CheckedAt, p.ValidUntil, e.Now, i.Policy.Bounds.LeaseSeconds) && p.ValidUntil <= e.Subject.ValidUntil && p.Binding.PrincipalID != "" && p.ConsentRef != "" && p.ConsentRevision != ""
}
func validatePrecanonicalSeal(i nativeVerifyInput) (json.RawMessage, string, string, error) {
	var s PrecanonicalAssociationEvidence
	if sourceDecode(i.Snapshot, &s, i.Policy.Bounds) != nil {
		return nil, "", "", sourceInvalid()
	}
	e := i.Expected
	if e.EnrollmentRef != nil || (e.Purpose == "identity.association.establish" && e.AssociationID != nil) || (e.Purpose == "identity.association.enroll" && e.AssociationID == nil) || (e.Purpose != "identity.association.establish" && e.Purpose != "identity.association.enroll") {
		return nil, "", "", sourceDenied()
	}
	if !nativeAssociationSealMatches(i, s.Evidence, s.CheckKey) {
		return nil, "", "", sourceDenied()
	}
	parent := i
	parent.Expected = nativeVerifyExpected{"nativeControlSnapshot", e.Subject, e.RequestID, "identity.mapping.prepare", s.ControlSnapshot.CheckKey, nil, nil, e.Now}
	if _, _, _, err := validateNativeControlSealWithParent(parent, s.ControlSnapshot); err != nil {
		return nil, "", "", err
	}
	if s.ControlSnapshot.Root.RootID != s.Evidence.Binding.OwnerRef.RootID || s.ControlSnapshot.Root.OwnerID != s.Evidence.NativeActorOwnerID || s.Evidence.ValidUntil > s.ControlSnapshot.ValidUntil {
		return nil, "", "", sourceDenied()
	}
	raw, err := unsignedNativeSnapshot(s)
	return raw, s.SealRef, "read", err
}
func validateNativeControlSealWithParent(i nativeVerifyInput, parent NativeControlSnapshot) (json.RawMessage, string, string, error) {
	raw, err := CanonicalDomainJSON(parent)
	if err != nil {
		return nil, "", "", sourceInvalid()
	}
	i.Snapshot = raw
	verified, err := CanonicalDomainJSON(i)
	if err != nil {
		return nil, "", "", sourceInvalid()
	}
	if _, err = VerifyNativeSourceSeal(verified); err != nil {
		return nil, "", "", err
	}
	return validateNativeControlSeal(i)
}

func (p *personalSource) currentConsent(e *canonicalSourceEntry, purpose, association string, enrollment SourceEnrollment) (CurrentNativeConsent, error) {
	if !existingEnrollmentMatches(enrollment, association) || (purpose != "identity.association.resolve" && purpose != "identity.association.enroll") || p.canonicalEntryCurrent(e) != nil {
		return CurrentNativeConsent{}, sourceDenied()
	}
	p.server.forestMutex.RLock()
	evidence, err := p.canonicalAssociationEvidenceLocked(e, purpose)
	p.server.forestMutex.RUnlock()
	if err != nil {
		return CurrentNativeConsent{}, err
	}
	result := CurrentNativeConsent{evidence, e.key, ""}
	result.SealRef, err = p.signNativeSnapshot(e, result, &association, &enrollment)
	return result, err
}
func (p *personalSource) canonicalAssociationEvidenceLocked(e *canonicalSourceEntry, purpose string) (NativeAssociationEvidence, error) {
	ledger := p.server.forest.PersonalBindings
	if ledger == nil {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	record, ok := ledger.Mappings[e.mapping.MappingID]
	consent, present := ledger.Consents[record.ConsentRef]
	if !ok || !present || !domainEqual(record.Mapping, e.mapping) || consent.State != "active" || consent.Revision != record.ConsentRevision || !p.mappedOwnerProfileCurrentLocked(e.mapping.Binding.OwnerRef.OwnerID) {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	native := e.mapping.Binding
	binding := core.PersonalBindingRecord{OwnerRef: native.OwnerRef, OwnerKind: "existing"}
	index, err := stagedForestIndex(p.server.forest)
	if err != nil || p.actualPersonalRootLocked(binding, index) != nil {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	if e.association != nil && !canonicalAssociationMatches(*e.association, record, consent, p.config) {
		return NativeAssociationEvidence{}, sourceDenied()
	}
	until := min(e.control.ValidUntil, e.subject.ValidUntil)
	if e.source != nil {
		until = min(e.source.ref.ValidUntil, e.subject.ValidUntil)
	}
	return NativeAssociationEvidence{SourceNativeBinding{native.PrincipalID, native.Account, native.OwnerRef}, p.config.SourceAuthorityRef, e.subject.Issuer, e.subject.Subject, e.subject.SessionID, native.OwnerRef.OwnerID, e.subject.RequestID, purpose, canonicalAssociationRevision(record), p.config.SourcePolicyRevision, consent.ConsentRef, consent.Revision, domainNow(), until}, nil
}
func (p *personalSource) canonicalDataEntryCurrent(e *canonicalSourceEntry) error {
	source := e.source
	if source == nil || source.closed || source.unknown || e.closing || e.subject.ValidUntil <= domainNow() || source.ref.ValidUntil <= domainNow() || source.read == nil || source.read.recheck() != nil {
		return sourceDenied()
	}
	if p.coordinator.subjectSessionFenced(e.subject) || p.coordinator.sessionFenced(enrollmentSessionKey{source.actor.PrincipalID, source.actor.SessionID}) {
		return sourceDenied()
	}
	p.server.forestMutex.RLock()
	defer p.server.forestMutex.RUnlock()
	ledger := p.server.forest.PersonalBindings
	if ledger == nil {
		return sourceDenied()
	}
	record, ok := ledger.Mappings[e.mapping.MappingID]
	if !ok || record.Binding == nil || e.mapping.Binding.PrincipalID != source.actor.PrincipalID || !domainEqual(record.Mapping, e.mapping) || e.mapping.Issuer != e.subject.Issuer || e.mapping.Subject != e.subject.Subject || !p.mappedOwnerProfileCurrentLocked(e.mapping.Binding.OwnerRef.OwnerID) {
		return sourceDenied()
	}
	index, err := stagedForestIndex(p.server.forest)
	if err != nil || p.actualPersonalRootLocked(*record.Binding, index) != nil {
		return sourceDenied()
	}
	return nil
}
func (p *personalSource) emitCurrentSeal(r SourceEnvelope) (interface{}, error) {
	var i mappingCurrentSeal
	if sourceDecode(r.Payload, &i, p.config.Bounds) != nil || i.CheckKey.Phase != "current" || !existingEnrollmentMatches(i.EnrollmentRef, i.AssociationID) {
		return nil, sourceInvalid()
	}
	e, err := p.currentSealEntry(r, i)
	if err != nil || !domainEqual(e.subject, i.Subject) || !domainEqual(e.key, i.CheckKey) || i.CheckKey.RawRequestSHA256 != e.originalSHA {
		return nil, sourceDenied()
	}
	return p.currentConsent(e, i.Purpose, i.AssociationID, i.EnrollmentRef)
}
func (p *personalSource) currentSealEntry(r SourceEnvelope, i mappingCurrentSeal) (*canonicalSourceEntry, error) {
	if i.LeaseRef.Kind == "control" {
		var ref ControlLeaseRef
		if sourceDecode(i.LeaseRef.Reference, &ref, p.config.Bounds) != nil {
			return nil, sourceInvalid()
		}
		return p.lookupControlLease(ref, r.RequestID)
	}
	if i.LeaseRef.Kind != "source" {
		return nil, sourceInvalid()
	}
	var ref SourceLeaseRef
	if sourceDecode(i.LeaseRef.Reference, &ref, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	source, err := p.lookupEntry(ref, r.RequestID)
	if err != nil || !source.canonicalFamily || source.originalSHA == "" || !sourceSubjectSame(source.actor.Evidence, i.Subject) {
		return nil, sourceDenied()
	}
	p.server.forestMutex.RLock()
	mapping, ok := p.sourceEntryMappingLocked(source, i.AssociationID, i.EnrollmentRef)
	var consent core.PersonalConsentRecord
	if ok {
		record := p.server.forest.PersonalBindings.Mappings[mapping.MappingID]
		consent = p.server.forest.PersonalBindings.Consents[record.ConsentRef]
	}
	p.server.forestMutex.RUnlock()
	if !ok {
		return nil, sourceDenied()
	}
	key := i.CheckKey
	if key.CommandID != consent.CommandID || key.ExpectedRevision == nil || *key.ExpectedRevision != consent.Revision || key.RawRequestSHA256 != source.originalSHA || key.StableCommandSHA256 != canonicalConsentDigest(mapping, key.CommandID, key.ExpectedRevision) {
		return nil, sourceDenied()
	}
	e := &canonicalSourceEntry{source: source, subject: i.Subject, key: key, mapping: mapping, read: source.read, seals: map[string]string{}, originalSHA: source.originalSHA, cleanupKnown: false}
	p.mu.Lock()
	source.canonical = e
	p.mu.Unlock()
	return e, nil
}
func (p *personalSource) sourceEntryMappingLocked(s *personalSourceEntry, id string, enrollment SourceEnrollment) (CanonicalResolvedMapping, bool) {
	ledger := p.server.forest.PersonalBindings
	if ledger == nil {
		return CanonicalResolvedMapping{}, false
	}
	var result CanonicalResolvedMapping
	count := 0
	for _, m := range ledger.Mappings {
		b := m.Binding
		if b != nil && b.AssociationID != nil && *b.AssociationID == id && domainEqual(b.Enrollment, enrollment) && b.PrincipalID == s.actor.PrincipalID && b.OwnerRef == s.owner && m.Mapping.Issuer == s.actor.Evidence.Issuer && m.Mapping.Subject == s.actor.Evidence.Subject {
			result = m.Mapping
			count++
		}
	}
	return result, count == 1
}

func validNativePolicyBounds(b PersonalSourceBounds) bool {
	return b.MaxContexts > 0 && b.MaxLeases > 0 && b.MaxSources > 0 && b.MaxBindings > 0 && b.MaxResources > 0 && b.MaxFields > 0 && b.MaxRetainedEpochs > 0 && domainFinite(b.RequestSeconds) && b.RequestSeconds > 0 && domainFinite(b.LeaseSeconds) && b.LeaseSeconds > 0
}
