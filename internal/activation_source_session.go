// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"sort"
	"strconv"
)

// This is the SAME admission coordinator for Manifest and personal entries.
// Roots remain in their actual owner/provider; no shadow root/account registry.
type sourceSession struct {
	admissions int
	fenced     bool
}
type sourceAdmission struct {
	coordinator *sourceCoordinator
	key         sourceSessionKey
	active      bool
}

func (c *sourceCoordinator) setSessionLimit(limit int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 || (c.limit != 0 && c.limit != limit) || len(c.sessions) > limit {
		return sourceInvalid()
	}
	c.limit = limit
	return nil
}
func (c *sourceCoordinator) reserveSession(key enrollmentSessionKey, limit int) (*sourceAdmission, error) {
	if c == nil {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if key.PrincipalID == "" || key.SessionID == "" || limit <= 0 {
		return nil, sourceInvalid()
	}
	if c.limit != 0 {
		limit = c.limit
	}
	state := c.sessions[canonicalSessionKey(key)]
	if state == nil && len(c.sessions) >= limit {
		return nil, sourceUnavailable()
	}
	if state == nil {
		state = &sourceSession{}
		c.sessions[canonicalSessionKey(key)] = state
	}
	if state.fenced {
		return nil, sourceDenied()
	}
	state.admissions++
	c.sessionGeneration++
	return &sourceAdmission{c, canonicalSessionKey(key), true}, nil
}
func (a *sourceAdmission) release() {
	if a == nil {
		return
	}
	c := a.coordinator
	c.mu.Lock()
	defer c.mu.Unlock()
	if a.active {
		c.sessions[a.key].admissions--
		c.sessionGeneration++
		a.active = false
		c.signalLocked()
	}
}
func (c *sourceCoordinator) fenceSession(key enrollmentSessionKey, limit int) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.sessions[canonicalSessionKey(key)]
	if state == nil && (limit <= 0 || len(c.sessions) >= limit) {
		return sourceUnavailable()
	}
	if state == nil {
		state = &sourceSession{}
		c.sessions[canonicalSessionKey(key)] = state
	}
	if !state.fenced {
		state.fenced = true
		c.sessionGeneration++
	}
	if state.admissions != 0 || c.unknown {
		return sourceUnavailable()
	}
	return nil
}
func (c *sourceCoordinator) sessionFenced(key enrollmentSessionKey) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.sessions[canonicalSessionKey(key)]
	return state != nil && state.fenced
}
func (c *sourceCoordinator) sessionSettled(key enrollmentSessionKey) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.sessions[canonicalSessionKey(key)]
	return !c.unknown && state != nil && state.fenced && state.admissions == 0
}

type SourceRootRef struct {
	Product  string         `json:"product"`
	Scope    SourceScope    `json:"scope"`
	OwnerRef SourceOwnerRef `json:"ownerRef"`
	Epoch    string         `json:"epoch"`
	HostID   string         `json:"hostId"`
	LeaseID  *string        `json:"leaseId"`
	Pending  bool           `json:"pending"`
}
type SourceRootSnapshot struct {
	SnapshotRef string          `json:"snapshotRef"`
	Generation  string          `json:"generation"`
	PrincipalID string          `json:"principalId"`
	SessionID   string          `json:"sessionId"`
	Roots       []SourceRootRef `json:"roots"`
	ValidUntil  float64         `json:"validUntil"`
}
type sourceRootSnapshotInput struct {
	PrincipalID string `json:"principalId"`
	SessionID   string `json:"sessionId"`
}
type sourceRootSnapshotRef struct {
	SnapshotRef string `json:"snapshotRef"`
}
type sourceRootState struct {
	Snapshot SourceRootSnapshot `json:"snapshot"`
	State    string             `json:"state"`
}
type sourceRootClose struct {
	RootRef     SourceRootRef `json:"rootRef"`
	PrincipalID string        `json:"principalId"`
	SessionID   string        `json:"sessionId"`
}
type sourceRootAck struct {
	RootRef     SourceRootRef `json:"rootRef"`
	PrincipalID string        `json:"principalId"`
	SessionID   string        `json:"sessionId"`
	Generation  string        `json:"generation"`
	State       string        `json:"state"`
}

func (p *personalSource) rootSnapshot(request SourceEnvelope) (interface{}, error) {
	var input sourceRootSnapshotInput
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	key := enrollmentSessionKey{input.PrincipalID, input.SessionID}
	if err := p.coordinator.fenceSession(key, p.config.Bounds.MaxLeases); err != nil {
		return nil, err
	}
	id, err := newDomainID()
	if err != nil {
		return nil, sourceUnavailable()
	}
	roots, err := p.actualPersonalRoots(key)
	if err != nil {
		return nil, err
	}
	snapshot := SourceRootSnapshot{id, p.rootGeneration(roots), input.PrincipalID, input.SessionID, roots, request.ValidUntil}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneExpiredSnapshotsLocked()
	if len(p.snapshots) >= p.config.Bounds.MaxLeases {
		return nil, sourceUnavailable()
	}
	p.snapshots[id] = snapshot
	return snapshot, nil
}
func (p *personalSource) rootGeneration(roots []SourceRootRef) string {
	p.coordinator.mu.Lock()
	generation := strconv.FormatUint(p.coordinator.generation, 10) + ":" + strconv.FormatUint(p.coordinator.sessionGeneration, 10)
	p.coordinator.mu.Unlock()
	return generation + ":" + sourceCommandKey(roots)
}
func (p *personalSource) actualPersonalRoots(key enrollmentSessionKey) ([]SourceRootRef, error) {
	roots := []SourceRootRef{}
	p.server.forestMutex.RLock()
	roots = p.ledgerPersonalRootsLocked(key)

	p.server.forestMutex.RUnlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, entry := range p.entries {
		if entry.closed || entry.actor.PrincipalID != key.PrincipalID || entry.actor.SessionID != key.SessionID || entry.owner.RootID == "" {
			continue
		}
		copy := id
		roots = append(roots, SourceRootRef{"momentum", entry.grant.Scope, entry.owner, p.epoch, p.config.HostID, &copy, true})
	}
	for _, entry := range p.candidates {
		if entry.actor.PrincipalID != key.PrincipalID || entry.actor.SessionID != key.SessionID || entry.source != nil || entry.state == "released" {
			continue
		}
		owner := SourceOwnerRef{entry.candidate.RuntimeID, entry.candidate.RootID, entry.candidate.OwnerID}
		roots = append(roots, SourceRootRef{"momentum", entry.grant.Scope, owner, p.epoch, p.config.HostID, nil, true})
	}
	if len(roots) > p.config.Bounds.MaxResources {
		return nil, sourceUnavailable()
	}
	sort.Slice(roots, func(i, j int) bool { return sourceCommandKey(roots[i]) < sourceCommandKey(roots[j]) })
	return roots, nil
}
func (p *personalSource) personalSessionDrained(key enrollmentSessionKey) bool {
	if !p.coordinator.sessionSettled(key) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, entry := range p.entries {
		if entry.actor.PrincipalID == key.PrincipalID && entry.actor.SessionID == key.SessionID && !entry.closed {
			return false
		}
	}
	for _, entry := range p.candidates {
		if entry.actor.PrincipalID == key.PrincipalID && entry.actor.SessionID == key.SessionID && entry.state != "released" {
			return false
		}
	}
	return true
}
func (p *personalSource) rootState(request SourceEnvelope, check bool) (interface{}, error) {
	var input sourceRootSnapshotRef
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	p.mu.Lock()
	snapshot, present := p.snapshots[input.SnapshotRef]
	p.mu.Unlock()
	if !present || snapshot.ValidUntil <= domainNow() {
		return nil, sourceDenied()
	}
	key := enrollmentSessionKey{snapshot.PrincipalID, snapshot.SessionID}
	roots, err := p.actualPersonalRoots(key)
	if err != nil {
		return nil, err
	}
	state := "closing"
	if p.personalSessionDrained(key) {
		state = "drained"
	}
	if check && (state != "drained" || snapshot.Generation != p.rootGeneration(roots) || !domainEqual(snapshot.Roots, roots)) {
		return nil, sourceUnavailable()
	}
	return sourceRootState{snapshot, state}, nil
}

func (p *personalSource) ledgerPersonalRootsLocked(key enrollmentSessionKey) []SourceRootRef {
	roots := []SourceRootRef{}
	ledger := p.server.forest.PersonalBindings
	if ledger == nil {
		return roots
	}
	for _, binding := range ledger.Bindings {
		if binding.PrincipalID == key.PrincipalID {
			roots = append(roots, SourceRootRef{"momentum", SourceScope{binding.Account.AccountID, "momentum"}, binding.OwnerRef, p.epoch, p.config.HostID, nil, false})
		}
	}
	return p.appendMappedPersonalRootsLocked(roots, key)
}

func (p *personalSource) rootClose(ctx context.Context, request SourceEnvelope) (interface{}, error) {
	var input sourceRootClose
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	key := enrollmentSessionKey{input.PrincipalID, input.SessionID}
	if !p.coordinator.sessionFenced(key) || !p.rootWasCaptured(input, key) {
		return nil, sourceDenied()
	}
	p.mu.Lock()
	entries := []*personalSourceEntry{}
	for _, entry := range p.entries {
		if entry.actor.PrincipalID == key.PrincipalID && entry.actor.SessionID == key.SessionID && entry.owner == input.RootRef.OwnerRef {
			entries = append(entries, entry)
		}
	}
	completed := p.cancelPreparedRootsLocked(input, key)
	notify := p.onComplete
	p.mu.Unlock()
	if notify != nil {
		for _, id := range completed {
			notify(id)
		}
	}
	for _, entry := range entries {
		if err := p.closeCapturedPersonal(ctx, entry); err != nil {
			return nil, err
		}
	}
	roots, err := p.actualPersonalRoots(key)
	if err != nil {
		return nil, err
	}
	state := "closing"
	if p.personalSessionDrained(key) {
		state = "drained"
	}
	return sourceRootAck{input.RootRef, input.PrincipalID, input.SessionID, p.rootGeneration(roots), state}, nil
}
func (p *personalSource) rootWasCaptured(input sourceRootClose, key enrollmentSessionKey) bool {
	if input.RootRef.Product != "momentum" || input.RootRef.Epoch != p.epoch || input.RootRef.HostID != p.config.HostID {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, snapshot := range p.snapshots {
		if snapshot.PrincipalID != key.PrincipalID || snapshot.SessionID != key.SessionID || snapshot.ValidUntil <= domainNow() {
			continue
		}
		if sourceContainsRoot(snapshot.Roots, input.RootRef) {
			return true
		}
	}
	return false
}
func sourceContainsRoot(roots []SourceRootRef, selected SourceRootRef) bool {
	for _, root := range roots {
		if domainEqual(root, selected) {
			return true
		}
	}
	return false
}
func (p *personalSource) cancelPreparedRootsLocked(input sourceRootClose, key enrollmentSessionKey) []string {
	completed := []string{}
	for id, entry := range p.candidates {
		owner := SourceOwnerRef{entry.candidate.RuntimeID, entry.candidate.RootID, entry.candidate.OwnerID}
		same := entry.actor.PrincipalID == key.PrincipalID && entry.actor.SessionID == key.SessionID && owner == input.RootRef.OwnerRef
		noEffect := entry.state == "prepared_no_effect" && entry.source == nil && entry.write == nil && entry.pending == nil && entry.snapshot.seq == 0
		if same && noEffect {
			entry.state = "released"
			completed = append(completed, id)
		}
	}
	return completed
}

func (p *personalSource) pruneExpiredSnapshotsLocked() {
	now := domainNow()
	for id, snapshot := range p.snapshots {
		if snapshot.ValidUntil <= now {
			delete(p.snapshots, id)
		}
	}
}

func (p *personalSource) expirePersonalPrepared(ref string) {
	p.mu.Lock()
	entry := p.candidates[ref]
	if entry == nil || entry.busy || entry.state != "prepared_no_effect" || entry.source != nil || entry.pending != nil || entry.write != nil {
		p.mu.Unlock()
		return
	}
	entry.state = "released"
	delete(p.candidates, ref)
	notify := p.onComplete
	p.mu.Unlock()
	p.coordinator.noteSourceChange()
	if notify != nil {
		notify(ref)
	}
}
func (p *personalSource) lookupReleaseEntry(ref SourceLeaseRef, requestID string) (*personalSourceEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.entries[ref.LeaseID]
	if entry == nil || entry.closed || !domainEqual(entry.ref, ref) || ref.RequestID != requestID || ref.Epoch != p.epoch || ref.HostID != p.config.HostID {
		return nil, sourceDenied()
	}
	return entry, nil
}
func (p *personalSource) releasePersonalSource(ctx context.Context, source *personalSourceEntry, disposition string) error {
	p.mu.Lock()
	entry := source.provision
	if entry == nil || entry.busy || entry.source != source {
		p.mu.Unlock()
		return sourceUnavailable()
	}
	entry.busy = true
	p.mu.Unlock()
	defer p.releasePersonalBusy(entry)
	if err := p.recoverPersonalWitness(ctx, entry); err != nil {
		return err
	}
	p.mu.Lock()
	noEffect := entry.pending == nil && entry.snapshot.seq == 0 && (entry.write == nil || !entry.write.owns(p.coordinator))
	known := entry.state == "committed" || noEffect
	if !known || source.unknown {
		p.mu.Unlock()
		return sourceUnavailable()
	}
	entry.state = "released"
	source.closed = true
	delete(p.entries, source.ref.LeaseID)
	delete(p.candidates, entry.candidate.CandidateRef)
	notify := p.onComplete
	p.mu.Unlock()
	p.coordinator.noteSourceChange()
	if notify != nil {
		notify(source.ref.LeaseID)
		notify(entry.candidate.CandidateRef)
	}
	return nil
}
func (c *sourceCoordinator) noteSourceChange() {
	c.mu.Lock()
	c.sessionGeneration++
	c.signalLocked()
	c.mu.Unlock()
}

func (p *personalSource) closeCapturedPersonal(ctx context.Context, entry *personalSourceEntry) error {
	if entry.provision != nil && !entry.guard {
		return p.releasePersonalSource(ctx, entry, "refused")
	}
	p.closeReadEntry(entry)
	return nil
}
