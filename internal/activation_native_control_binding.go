// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"strconv"
	"strings"
	"time"
)

func canonicalNativeEpoch(raw string) bool {
	v, err := strconv.ParseInt(raw, 10, 64)
	return err == nil && v >= 0 && strconv.FormatInt(v, 10) == raw
}
func (p *personalSource) captureNativeControl(request SourceEnvelope) (interface{}, error) {
	var i nativeControlCapture
	if sourceDecode(request.Payload, &i, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	if p.server.nativeControl.Load() == nil {
		return nil, sourceUnavailable()
	}
	key := p.server.sessionKeyFromBearer(i.NativeControlCredential)
	if !strings.HasPrefix(i.NativeControlCredential, "ms_") {
		claims, refusal := p.server.legacySessionClaims(i.NativeControlCredential)
		if refusal != "" || claims == nil || claims.SessionID != key {
			return nil, sourceDenied()
		}
	}
	p.server.forestMutex.RLock()
	session, valid := p.server.registeredSessionLocked(key, time.Now().Unix())
	root, epoch, err := p.selectNativeRootLocked(session, i.RootID)
	p.server.forestMutex.RUnlock()
	if !valid || err != nil || key == "" {
		return nil, sourceDenied()
	}
	id, err := newDomainID()
	if err != nil {
		return nil, sourceUnavailable()
	}
	sessionRef, err := newDomainID()
	if err != nil {
		return nil, sourceUnavailable()
	}
	ref := SourceControlRef{id, p.epoch, min(float64(applicationSessionDeadline(session)), request.ValidUntil, domainNow()+p.config.Bounds.LeaseSeconds)}
	held := sourceControlEntry{ref, key, session.UserID}
	e := &canonicalSourceEntry{held: held, facts: nativeControlFacts{root, sessionRef, session, epoch}, seals: map[string]string{}, cleanupKnown: true}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneExpiredControlsLocked()
	if len(p.entries)+len(p.candidates) >= p.config.Bounds.MaxLeases || len(p.controls) >= p.config.Bounds.MaxSources || ref.ValidUntil <= domainNow() {
		return nil, sourceUnavailable()
	}
	time.AfterFunc(time.Duration((ref.ValidUntil-domainNow())*float64(time.Second)), func() { p.expireCapturedControl(id) })
	p.controls[id] = held
	p.entries[id] = &personalSourceEntry{canonical: e, owner: SourceOwnerRef{RuntimeID: p.server.forest.ID, RootID: root, OwnerID: session.UserID}}
	return ref, nil
}
func (p *personalSource) selectNativeRootLocked(session core.ApplicationSession, selected *string) (string, int64, error) {
	profile, err := p.server.forest.GetUserProfile(session.UserID)
	if err != nil || session.CredentialEpoch < 0 || profile.CredentialEpoch < 0 {
		return "", 0, sourceDenied()
	}
	roots := []string{}
	for id, node := range p.server.forest.Children {
		if selected != nil && *selected != id {
			continue
		}
		binding := core.PersonalBindingRecord{OwnerRef: SourceOwnerRef{RuntimeID: p.server.forest.ID, RootID: id, OwnerID: session.UserID}, OwnerKind: "existing"}
		if p.actualPersonalRootLocked(binding, map[string]*core.Node{id: node}) == nil {
			roots = append(roots, id)
		}
	}
	if len(roots) != 1 {
		return "", 0, sourceDenied()
	}
	return roots[0], profile.CredentialEpoch, nil
}
func (p *personalSource) capturedControl(id string) (*canonicalSourceEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	source := p.entries[id]
	if source == nil || source.closed || source.canonical == nil || source.canonical.held.ref.ControlRef != id || source.canonical.closing || source.canonical.unknown {
		return nil, sourceDenied()
	}
	return source.canonical, nil
}
func (p *personalSource) currentNativeControlLocked(e *canonicalSourceEntry) error {
	if e.held.ref.Epoch != p.epoch || e.held.ref.ValidUntil <= domainNow() {
		return sourceDenied()
	}
	session, valid := p.server.registeredSessionLocked(e.held.key, time.Now().Unix())
	profile, err := p.server.forest.GetUserProfile(e.held.ownerID)
	if !valid || err != nil || !domainEqual(session, e.facts.session) || profile.CredentialEpoch != e.facts.profileEpoch {
		return sourceDenied()
	}
	binding := core.PersonalBindingRecord{OwnerRef: SourceOwnerRef{RuntimeID: p.server.forest.ID, RootID: e.facts.rootID, OwnerID: e.held.ownerID}, OwnerKind: "existing"}
	index, err := stagedForestIndex(p.server.forest)
	if err != nil || p.actualPersonalRootLocked(binding, index) != nil {
		return sourceDenied()
	}
	return nil
}
func (p *personalSource) openNativeControl(request SourceEnvelope) (interface{}, error) {
	var i nativeControlOpen
	if sourceDecode(request.Payload, &i, p.config.Bounds) != nil || i.Purpose != "identity.mapping.prepare" || !domainValidHash(i.RawRequestSHA256) {
		return nil, sourceInvalid()
	}
	captured, err := p.capturedControl(i.ControlRef)
	if err != nil {
		return nil, err
	}
	key := MappingCheckKey{i.CommandID, request.RequestID, i.RawRequestSHA256, "", i.ExpectedRevision, "prepare"}
	entry, err := p.registerControlEntry(request, i.Subject, captured, key, nil)
	if err != nil {
		return nil, err
	}
	snapshot, err := p.buildControlSnapshot(entry, "identity.mapping.prepare", "prepare")
	if err != nil {
		p.releaseCanonicalEntry(entry, true)
		return nil, err
	}
	entry.key = snapshot.CheckKey
	entry.snapshot = snapshot
	entry.control.ControlSnapshotSHA256 = sourceCommandKey(snapshot)
	return struct {
		LeaseRef ControlLeaseRef       `json:"leaseRef"`
		Snapshot NativeControlSnapshot `json:"snapshot"`
	}{entry.control, snapshot}, nil
}
func (p *personalSource) registerControlEntry(r SourceEnvelope, subject SourceSubjectEvidence, captured *canonicalSourceEntry, key MappingCheckKey, writer *sourceWritePermit) (*canonicalSourceEntry, error) {
	if validateSourceSubject(subject, r.RequestID, p.config.Bounds) != nil {
		return nil, sourceDenied()
	}
	admission, err := p.coordinator.reserveSubjectSession(subject, p.config.Bounds.MaxLeases)
	if err != nil {
		return nil, err
	}
	defer admission.release()
	read, err := p.coordinator.beginRead(writer)
	if err != nil {
		return nil, err
	}
	id, err := newDomainID()
	if err != nil {
		read.release()
		return nil, sourceUnavailable()
	}
	until := min(captured.held.ref.ValidUntil, subject.ValidUntil, r.ValidUntil, domainNow()+p.config.Bounds.LeaseSeconds)
	revision := p.server.sourceForestRevision()
	entry := &canonicalSourceEntry{control: ControlLeaseRef{p.epoch, p.config.HostID, id, r.RequestID, captured.held.ref.ControlRef, "", revision, until}, held: captured.held, facts: captured.facts, subject: subject, key: key, read: read, write: writer, seals: map[string]string{}, cleanupKnown: true, originalSHA: stagedHash(r.Payload), originalAction: r.Action}
	p.mu.Lock()
	defer p.mu.Unlock()
	if until <= domainNow() || revision == "" || len(p.entries)+len(p.candidates) >= p.config.Bounds.MaxLeases {
		read.release()
		return nil, sourceUnavailable()
	}
	p.entries[id] = &personalSourceEntry{canonical: entry, owner: SourceOwnerRef{RuntimeID: p.server.forest.ID, RootID: entry.facts.rootID, OwnerID: entry.held.ownerID}}
	p.coordinator.noteSourceChange()
	return entry, nil
}
func (p *personalSource) canonicalEntryCurrent(e *canonicalSourceEntry) error {
	if e != nil && e.source != nil {
		return p.canonicalDataEntryCurrent(e)
	}
	if e == nil || e.closing || e.unknown || e.subject.ValidUntil <= domainNow() || e.control.ValidUntil <= domainNow() || e.read == nil || e.read.recheck() != nil || p.coordinator.subjectSessionFenced(e.subject) {
		return sourceDenied()
	}
	p.server.forestMutex.RLock()
	defer p.server.forestMutex.RUnlock()
	return p.currentNativeControlLocked(e)
}
func (p *personalSource) buildControlSnapshot(e *canonicalSourceEntry, purpose, phase string) (NativeControlSnapshot, error) {
	if p.canonicalEntryCurrent(e) != nil {
		return NativeControlSnapshot{}, sourceDenied()
	}
	p.server.forestMutex.RLock()
	snapshot, err := p.controlSnapshotLocked(e, purpose, phase)
	p.server.forestMutex.RUnlock()
	if err != nil {
		return snapshot, err
	}
	snapshot.SealRef, err = p.signNativeSnapshot(e, snapshot, nil, nil)
	return snapshot, err
}
func (p *personalSource) controlSnapshotLocked(e *canonicalSourceEntry, purpose, phase string) (NativeControlSnapshot, error) {
	root := p.server.forest.Children[e.facts.rootID]
	if root == nil || p.currentNativeControlLocked(e) != nil {
		return NativeControlSnapshot{}, sourceDenied()
	}
	raw, err := encodeState(root)
	if err != nil {
		return NativeControlSnapshot{}, sourceUnavailable()
	}
	lineage := sourceCommandKey([]interface{}{p.server.forest.ID, root.ID, root.CreatedBy, root.Parents, p.server.forest.Name})
	source := NativeControlSource{p.config.SourceAuthorityRef, p.server.forest.ID, p.config.HostID, p.epoch, p.server.sourceForestRevisionLocked(), p.config.SourcePolicyRevision}
	control := NativeControlKey{e.held.ref.ControlRef, e.facts.sessionRef, e.held.ownerID, strconv.FormatInt(e.facts.session.CredentialEpoch, 10)}
	owned := ExistingRootKey{root.ID, e.held.ownerID, root.CreatedBy, stagedHash(raw), lineage}
	key := e.key
	key.Phase = phase
	if purpose == "identity.mapping.prepare" {
		key.StableCommandSHA256 = canonicalPrepareDigest(e.subject, source, owned, key.ExpectedRevision)
	}
	return NativeControlSnapshot{source, control, owned, e.subject, e.control.RequestID, purpose, key, domainNow(), min(e.control.ValidUntil, e.subject.ValidUntil), ""}, nil
}
func canonicalPrepareDigest(s SourceSubjectEvidence, source NativeControlSource, root ExistingRootKey, revision *string) string {
	return sourceCommandKey(map[string]interface{}{"operation": "identity.mapping.prepare", "issuer": s.Issuer, "subject": s.Subject, "nativeAuthorityRef": source.NativeAuthorityRef, "runtimeId": source.RuntimeID, "rootId": root.RootID, "ownerId": root.OwnerID, "sourcePolicyRevision": source.SourcePolicyRevision, "expectedRevision": revision})
}
func (p *personalSource) lookupControlLease(ref ControlLeaseRef, request string) (*canonicalSourceEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	source := p.entries[ref.LeaseID]
	if source == nil || source.closed || source.canonical == nil || !domainEqual(source.canonical.control, ref) || ref.RequestID != request {
		return nil, sourceDenied()
	}
	return source.canonical, nil
}
func (p *personalSource) recheckNativeControl(r SourceEnvelope) (interface{}, error) {
	var i nativeControlRecheck
	if sourceDecode(r.Payload, &i, p.config.Bounds) != nil || i.Purpose != "identity.mapping.prepare" {
		return nil, sourceInvalid()
	}
	e, err := p.lookupControlLease(i.LeaseRef, r.RequestID)
	if err != nil || !domainEqual(e.subject, i.Subject) || !domainEqual(e.key, i.CheckKey) || p.canonicalEntryCurrent(e) != nil {
		return nil, sourceDenied()
	}
	return e.snapshot, nil // SAME issued facts/expiry/seal; no timestamp renewal.
}
func (p *personalSource) releaseNativeControl(r SourceEnvelope) (interface{}, error) {
	var i nativeControlRelease
	if sourceDecode(r.Payload, &i, p.config.Bounds) != nil || !domainContains([]string{"released", "refused", "unknown"}, i.Disposition) {
		return nil, sourceInvalid()
	}
	e, err := p.lookupControlLease(i.LeaseRef, r.RequestID)
	if err != nil {
		return nil, err
	}
	if i.Disposition == "unknown" {
		return nil, sourceUnavailable()
	}
	if e.unknown {
		if err = p.recoverCanonicalWitness(context.Background(), e); err != nil {
			return nil, err
		}
		return sourceReleaseAck{e.control.LeaseID, p.epoch, "released"}, nil
	}
	if !e.cleanupKnown {
		return nil, sourceUnavailable()
	}
	p.releaseCanonicalEntry(e, true)
	return sourceReleaseAck{e.control.LeaseID, p.epoch, "released"}, nil
}
func (p *personalSource) releaseCanonicalEntry(e *canonicalSourceEntry, known bool) {
	p.mu.Lock()
	if !known || e.unknown || !e.cleanupKnown {
		e.closing = true
		p.mu.Unlock()
		return
	}
	delete(p.entries, e.control.LeaseID)
	complete := p.onComplete
	p.mu.Unlock()
	if e.read != nil {
		e.read.release()
	}
	p.coordinator.noteSourceChange()
	if complete != nil {
		complete(e.control.LeaseID)
	}
}
func existingEnrollmentMatches(e SourceEnrollment, association string) bool {
	return e.CommandID != "" && e.Revision != "" && e.Enrollment.Mode == "existing" && e.Enrollment.ExistingIdentityRef != nil && *e.Enrollment.ExistingIdentityRef == association
}

func (p *personalSource) openPrecanonicalIdentity(r SourceEnvelope) (interface{}, error) {
	var i precanonicalIdentityOpen
	if sourceDecode(r.Payload, &i, p.config.Bounds) != nil || (i.Purpose != "identity.association.establish" && i.Purpose != "identity.association.enroll") || (i.Purpose == "identity.association.establish" && i.Record != nil) || (i.Purpose == "identity.association.enroll" && i.Record == nil) {
		return nil, sourceInvalid()
	}
	record, captured, err := p.precanonicalSourceRecord(i)
	if err != nil {
		return nil, err
	}
	expected := record.ConsentRevision
	key := MappingCheckKey{record.Mapping.MappingID, r.RequestID, stagedHash(r.Payload), "", &expected, "current"}
	p.server.forestMutex.RLock()
	consent := p.server.forest.PersonalBindings.Consents[record.ConsentRef]
	p.server.forestMutex.RUnlock()
	key.CommandID = consent.CommandID
	key.StableCommandSHA256 = canonicalConsentDigest(record.Mapping, key.CommandID, key.ExpectedRevision)
	e, err := p.registerControlEntry(r, i.Subject, captured, key, nil)
	if err != nil {
		return nil, err
	}
	e.mapping, e.association = record.Mapping, i.Record
	snapshot, err := p.buildControlSnapshot(e, "identity.mapping.prepare", "prepare")
	if err != nil {
		p.releaseCanonicalEntry(e, true)
		return nil, err
	}
	e.snapshot = snapshot
	e.control.ControlSnapshotSHA256 = sourceCommandKey(snapshot)
	p.server.forestMutex.RLock()
	evidence, err := p.canonicalAssociationEvidenceLocked(e, i.Purpose)
	p.server.forestMutex.RUnlock()
	if err != nil {
		p.releaseCanonicalEntry(e, true)
		return nil, err
	}
	proof := PrecanonicalAssociationEvidence{snapshot, evidence, key, ""}
	var association *string
	if i.Record != nil {
		association = &i.Record.AssociationID
	}
	proof.SealRef, err = p.signNativeSnapshot(e, proof, association, nil)
	if err != nil {
		p.releaseCanonicalEntry(e, true)
		return nil, err
	}
	return struct {
		ControlLeaseRef ControlLeaseRef                 `json:"controlLeaseRef"`
		Proof           PrecanonicalAssociationEvidence `json:"proof"`
	}{e.control, proof}, nil
}
func (p *personalSource) precanonicalSourceRecord(i precanonicalIdentityOpen) (core.PersonalMappingRecord, *canonicalSourceEntry, error) {
	attach := canonicalAttachInput{Subject: i.Subject}
	p.server.forestMutex.RLock()
	ledger := p.server.forest.PersonalBindings
	count := 0
	if ledger == nil {
		p.server.forestMutex.RUnlock()
		return core.PersonalMappingRecord{}, nil, sourceDenied()
	}
	for _, m := range ledger.Mappings {
		if m.ConsentRef != i.NativeEvidenceRef || m.Mapping.Issuer != i.Subject.Issuer || m.Mapping.Subject != i.Subject.Subject {
			continue
		}
		attach.Record = SourceAssociationRecord{ConsentRef: m.ConsentRef, Binding: SourceNativeBinding{m.Mapping.Binding.PrincipalID, m.Mapping.Binding.Account, m.Mapping.Binding.OwnerRef}}
		count++
	}
	p.server.forestMutex.RUnlock()
	if count != 1 {
		return core.PersonalMappingRecord{}, nil, sourceDenied()
	}
	if i.Record != nil {
		attach.Record = *i.Record
	}
	return p.attachSourceRecord(attach)
}

// A capture has no effects or callback worker. Operational leases own their
// copied facts and permits separately; expiry never discards unknown effects.
func (p *personalSource) expireCapturedControl(id string) {
	p.mu.Lock()
	entry := p.entries[id]
	if entry == nil || entry.canonical == nil || entry.canonical.control.LeaseID != "" || entry.canonical.held.ref.ValidUntil > domainNow() {
		p.mu.Unlock()
		return
	}
	delete(p.entries, id)
	delete(p.controls, id)
	notify := p.onComplete
	p.mu.Unlock()
	if notify != nil {
		notify(id)
	}
}

// Restart restores facts from ONE actual loaded ledger/root pair, never rights.
func (s *Server) validateCanonicalStagedDescriptorLocked(d stagedDescriptor) error {
	root := s.forest.Children[d.Binding.RootID]
	if d.SourceProfile == "" {
		if root != nil && preservedStagedNode(root) {
			return sourceDenied()
		}
		return nil
	}
	if d.SourceProfile != personalExistingProfile || d.Binding.ProductID != "momentum" || root == nil || s.forest.PersonalBindings == nil {
		return sourceDenied()
	}
	ledger := s.forest.PersonalBindings
	var selected core.PersonalMappingRecord
	count := 0
	for _, record := range ledger.Mappings {
		m := record.Mapping
		if canonicalScopeID(m.MappingID) != d.Binding.ScopeID {
			continue
		}
		selected = record
		count++
	}
	if count != 1 || !canonicalDescriptorBindingMatches(s, d, selected, root) {
		return sourceDenied()
	}
	c, ok := ledger.Consents[selected.ConsentRef]
	m := selected.Mapping
	if !ok || c.MappingRef != m.MappingID || c.RootID != root.ID || c.NativeOwnerID != root.CreatedBy || c.Issuer != m.Issuer || c.Subject != m.Subject || c.Revision != selected.ConsentRevision || !domainContains([]string{"active", "revoked"}, c.State) {
		return sourceDenied()
	}
	return validateCanonicalHistoryPair(root, d, selected)
}
func canonicalDescriptorBindingMatches(s *Server, d stagedDescriptor, r core.PersonalMappingRecord, root *core.Node) bool {
	m, b := r.Mapping, d.Binding
	if m.Binding.OwnerRef.RuntimeID != s.forest.ID || m.Binding.OwnerRef.RootID != root.ID || m.Binding.OwnerRef.OwnerID != root.CreatedBy || b.AccountRootID != s.forest.ID || b.AccountID != m.Binding.Account.AccountID || b.BindingRevision != m.MappingRevision {
		return false
	}
	if root.Kind != "workspace" || root.Metadata["personal_owner"] != root.CreatedBy || !root.CheckPermission(root.CreatedBy, core.AdminPermission) || len(root.Parents) != 1 || root.Parents[s.forest.ID] != s.forest.Name {
		return false
	}
	_, err := s.forest.GetUserProfile(root.CreatedBy)
	return err == nil
}
func validateCanonicalHistoryPair(root *core.Node, d stagedDescriptor, r core.PersonalMappingRecord) error {
	if len(r.History) == 0 {
		return sourceDenied()
	}
	for _, h := range r.History {
		raw, err := json.Marshal(root.CommandReceipts[h.ReceiptKey])
		if err != nil {
			return sourceDenied()
		}
		pair, err := stagedReceiptPair(d.Binding, h.ReceiptKey, raw)
		if err != nil || pair.ScopeID != d.Binding.ScopeID {
			return sourceDenied()
		}
		var receipt stagedReceipt
		var binding stagedBinding
		if decodeStagedProductReceipt(raw, &receipt, d.Bounds.MaxScopeBytes) != nil || sourceDecode(h.Binding, &binding, PersonalSourceBounds{MaxRequestBytes: d.Bounds.MaxScopeBytes}) != nil || binding != d.Binding {
			return sourceDenied()
		}
		if receipt.Command.BodySHA256 != h.StableSHA256 || receipt.Command.CommandID != h.CommandID || receipt.Command.Action != h.Operation || receipt.Command.PrincipalID != r.Mapping.Binding.PrincipalID || len(receipt.MappingRecord) == 0 {
			return sourceDenied()
		}
	}
	return nil
}
