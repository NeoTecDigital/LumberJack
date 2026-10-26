// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"sort"
)

// SAME coordinator map, tagged genuine canonical or preprincipal identity.
type sourceSessionKey struct{ PrincipalID, Issuer, Subject, SessionID string }

func canonicalSessionKey(k enrollmentSessionKey) sourceSessionKey {
	return sourceSessionKey{PrincipalID: k.PrincipalID, SessionID: k.SessionID}
}
func subjectSessionKey(s SourceSubjectEvidence) sourceSessionKey {
	return sourceSessionKey{Issuer: s.Issuer, Subject: s.Subject, SessionID: s.SessionID}
}
func (c *sourceCoordinator) reserveSubjectSession(s SourceSubjectEvidence, limit int) (*sourceAdmission, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := subjectSessionKey(s)
	if key.Issuer == "" || key.Subject == "" || key.SessionID == "" || limit <= 0 {
		return nil, sourceInvalid()
	}
	if c.limit != 0 {
		limit = c.limit
	}
	state := c.sessions[key]
	if state == nil && len(c.sessions) >= limit {
		return nil, sourceUnavailable()
	}
	if state == nil {
		state = &sourceSession{}
		c.sessions[key] = state
	}
	if state.fenced {
		return nil, sourceDenied()
	}
	state.admissions++
	c.sessionGeneration++
	return &sourceAdmission{c, key, true}, nil
}
func (c *sourceCoordinator) subjectSessionFenced(s SourceSubjectEvidence) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.sessions[subjectSessionKey(s)]
	return state != nil && state.fenced
}
func (c *sourceCoordinator) fenceSubject(s SourceSubjectEvidence, limit int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := subjectSessionKey(s)
	state := c.sessions[key]
	if state == nil && len(c.sessions) >= limit {
		return sourceUnavailable()
	}
	if state == nil {
		state = &sourceSession{}
		c.sessions[key] = state
	}
	if !state.fenced {
		state.fenced = true
		c.sessionGeneration++
		c.signalLocked()
	}
	if state.admissions != 0 || c.unknown {
		return sourceUnavailable()
	}
	return nil
}

type pendingSubjectRoot struct {
	Issuer          string          `json:"issuer"`
	Subject         string          `json:"subject"`
	SessionID       string          `json:"sessionId"`
	PendingRef      string          `json:"pendingRef"`
	RuntimeID       string          `json:"runtimeId"`
	HostID          string          `json:"hostId"`
	Epoch           string          `json:"epoch"`
	RootID          string          `json:"rootId"`
	ControlLeaseRef ControlLeaseRef `json:"controlLeaseRef"`
	ValidUntil      float64         `json:"validUntil"`
}
type subjectRootIdentity struct {
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject"`
	SessionID string `json:"sessionId"`
}
type subjectRootsInput struct {
	Subject     SourceSubjectEvidence `json:"subject"`
	PrincipalID *string               `json:"principalId"`
}
type subjectRootsSnapshot struct {
	SnapshotRef string               `json:"snapshotRef"`
	Generation  string               `json:"generation"`
	Subject     subjectRootIdentity  `json:"subject"`
	PrincipalID *string              `json:"principalId"`
	Roots       []pendingSubjectRoot `json:"roots"`
	ValidUntil  float64              `json:"validUntil"`
}
type subjectRootsClose struct {
	RootRef pendingSubjectRoot    `json:"rootRef"`
	Subject SourceSubjectEvidence `json:"subject"`
}
type canonicalRootSnapshotEntry struct {
	snapshot subjectRootsSnapshot
	subject  SourceSubjectEvidence
}

func (p *personalSource) subjectRoots(r SourceEnvelope, _ bool) (interface{}, error) {
	var i subjectRootsInput
	if sourceDecode(r.Payload, &i, p.config.Bounds) != nil || validateSourceSubject(i.Subject, r.RequestID, p.config.Bounds) != nil {
		return nil, sourceDenied()
	}
	if err := p.fenceActualSubject(i.Subject, i.PrincipalID); err != nil {
		return nil, err
	}
	id, err := newDomainID()
	if err != nil {
		return nil, sourceUnavailable()
	}
	roots := p.pendingSubjectRoots(i.Subject)
	if len(roots) > p.config.Bounds.MaxResources {
		return nil, sourceUnavailable()
	}
	s := subjectRootsSnapshot{id, p.subjectRootGeneration(roots), subjectRootIdentity{i.Subject.Issuer, i.Subject.Subject, i.Subject.SessionID}, i.PrincipalID, roots, min(r.ValidUntil, i.Subject.ValidUntil)}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.subjectSnapshots == nil {
		p.subjectSnapshots = map[string]canonicalRootSnapshotEntry{}
	}
	for key, v := range p.subjectSnapshots {
		if v.snapshot.ValidUntil <= domainNow() {
			delete(p.subjectSnapshots, key)
		}
	}
	if len(p.subjectSnapshots)+len(p.snapshots) >= p.config.Bounds.MaxLeases {
		return nil, sourceUnavailable()
	}
	p.subjectSnapshots[id] = canonicalRootSnapshotEntry{s, i.Subject}
	return s, nil
}
func (p *personalSource) fenceActualSubject(s SourceSubjectEvidence, principal *string) error {
	if principal != nil {
		p.server.forestMutex.RLock()
		valid := p.subjectPrincipalLocked(s, *principal)
		p.server.forestMutex.RUnlock()
		if !valid {
			return sourceDenied()
		}
		if err := p.coordinator.fenceSession(enrollmentSessionKey{*principal, s.SessionID}, p.config.Bounds.MaxLeases); err != nil {
			return err
		}
	}
	return p.coordinator.fenceSubject(s, p.config.Bounds.MaxLeases)
}
func (p *personalSource) subjectPrincipalLocked(s SourceSubjectEvidence, id string) bool {
	ledger := p.server.forest.PersonalBindings
	if ledger == nil {
		return false
	}
	for _, r := range ledger.Mappings {
		if r.Mapping.Issuer == s.Issuer && r.Mapping.Subject == s.Subject && r.Mapping.Binding.PrincipalID == id && r.Binding != nil {
			return true
		}
	}
	return false
}
func (p *personalSource) pendingSubjectRoots(s SourceSubjectEvidence) []pendingSubjectRoot {
	p.mu.Lock()
	defer p.mu.Unlock()
	roots := []pendingSubjectRoot{}
	for id, entry := range p.entries {
		e := entry.canonical
		if entry.closed || e == nil || e.control.LeaseID == "" || e.subject.Issuer != s.Issuer || e.subject.Subject != s.Subject || e.subject.SessionID != s.SessionID {
			continue
		}
		roots = append(roots, pendingSubjectRoot{s.Issuer, s.Subject, s.SessionID, id, p.server.forest.ID, p.config.HostID, p.epoch, e.facts.rootID, e.control, e.control.ValidUntil})
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].PendingRef < roots[j].PendingRef })
	return roots
}
func (p *personalSource) subjectRootGeneration(roots []pendingSubjectRoot) string {
	p.coordinator.mu.Lock()
	value := []interface{}{p.coordinator.generation, p.coordinator.sessionGeneration, roots}
	p.coordinator.mu.Unlock()
	return sourceCommandKey(value)
}
func (p *personalSource) subjectRootsState(r SourceEnvelope, check bool) (interface{}, error) {
	var i sourceRootSnapshotRef
	if sourceDecode(r.Payload, &i, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	p.mu.Lock()
	held, ok := p.subjectSnapshots[i.SnapshotRef]
	p.mu.Unlock()
	if !ok || held.snapshot.ValidUntil <= domainNow() {
		return nil, sourceDenied()
	}
	roots := p.pendingSubjectRoots(held.subject)
	state := "closing"
	if len(roots) == 0 && p.subjectSessionSettled(held.subject) {
		state = "drained"
	}
	if check && (state != "drained" || held.snapshot.Generation != p.subjectRootGeneration(roots) || !domainEqual(held.snapshot.Roots, roots)) {
		return nil, sourceUnavailable()
	}
	return struct {
		Snapshot subjectRootsSnapshot `json:"snapshot"`
		State    string               `json:"state"`
	}{held.snapshot, state}, nil
}
func (p *personalSource) subjectSessionSettled(s SourceSubjectEvidence) bool {
	p.coordinator.mu.Lock()
	defer p.coordinator.mu.Unlock()
	state := p.coordinator.sessions[subjectSessionKey(s)]
	return state != nil && state.fenced && state.admissions == 0 && !p.coordinator.unknown
}
func (p *personalSource) subjectRootsClose(_ context.Context, r SourceEnvelope) (interface{}, error) {
	var i subjectRootsClose
	if sourceDecode(r.Payload, &i, p.config.Bounds) != nil || validateSourceSubject(i.Subject, r.RequestID, p.config.Bounds) != nil || !p.coordinator.subjectSessionFenced(i.Subject) {
		return nil, sourceDenied()
	}
	p.mu.Lock()
	valid := p.subjectRootCapturedLocked(i.RootRef, i.Subject)
	entry := p.entries[i.RootRef.PendingRef]
	if valid && entry != nil && entry.canonical != nil {
		entry.canonical.closing = true
	}
	p.mu.Unlock()
	if !valid {
		return nil, sourceDenied()
	}
	roots := p.pendingSubjectRoots(i.Subject)
	state := "closing"
	if len(roots) == 0 && p.subjectSessionSettled(i.Subject) {
		state = "drained"
	}
	return struct {
		RootRef    pendingSubjectRoot `json:"rootRef"`
		Generation string             `json:"generation"`
		State      string             `json:"state"`
	}{i.RootRef, p.subjectRootGeneration(roots), state}, nil
}
func (p *personalSource) subjectRootCapturedLocked(root pendingSubjectRoot, s SourceSubjectEvidence) bool {
	for _, held := range p.subjectSnapshots {
		if !sourceSubjectSame(held.subject, s) || held.snapshot.ValidUntil <= domainNow() {
			continue
		}
		if pendingSubjectContains(held.snapshot.Roots, root) {
			return true
		}
	}
	return false
}
func (p *personalSource) appendMappedPersonalRootsLocked(roots []SourceRootRef, key enrollmentSessionKey) []SourceRootRef {
	ledger := p.server.forest.PersonalBindings
	if ledger == nil {
		return roots
	}
	for _, record := range ledger.Mappings {
		if record.Binding == nil || record.Binding.PrincipalID != key.PrincipalID {
			continue
		}
		b := record.Binding
		root := SourceRootRef{"momentum", SourceScope{b.Account.AccountID, "momentum"}, b.OwnerRef, p.epoch, p.config.HostID, nil, false}
		if !sourceContainsRoot(roots, root) {
			roots = append(roots, root)
		}
	}
	return roots
}

func pendingSubjectContains(roots []pendingSubjectRoot, root pendingSubjectRoot) bool {
	for _, actual := range roots {
		if domainEqual(actual, root) {
			return true
		}
	}
	return false
}
