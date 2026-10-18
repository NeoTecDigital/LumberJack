// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"crypto/subtle"
	"fmt"
	"math"
)

func (d *domainEngine) reserve(actor DomainVerified, input DomainInput, owned DomainOwnedScope) (*domainEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := DomainGateKey{actor.PrincipalID, actor.SessionID, actor.Scope}
	if actor.ExpiresAt <= domainNow() || d.closed[key] || len(d.entries) >= d.config.MaxLeases {
		return nil, fmt.Errorf("domain gate closed/expired/full")
	}
	id, err := newDomainID()
	if err != nil {
		return nil, err
	}
	fingerprint, err := DomainIntentHash(actor.Intent)
	if err != nil {
		return nil, err
	}
	lease := DomainLease{d.epoch, id, actor.PrincipalID, actor.SessionID, actor.Scope, actor.Intent.Binding, fingerprint}
	entry := &domainEntry{lease: lease, intent: actor.Intent, input: input, actor: actor, owned: owned, product: d.products[actor.Scope.Product], executing: true}
	d.entries[id] = entry
	return entry, nil
}
func (d *domainEngine) entry(input DomainControl) (*domainEntry, error) {
	if input.Epoch != d.epoch || input.HostID != d.config.HostID || subtle.ConstantTimeCompare([]byte(input.ChannelToken), []byte(d.config.ControlToken)) != 1 {
		return nil, fmt.Errorf("private native lease channel denied")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	entry := d.entries[input.LeaseID]
	if entry == nil {
		return nil, fmt.Errorf("native lease unavailable")
	}
	return entry, nil
}
func (s *Server) DomainControl(ctx context.Context, input DomainControl) (DomainControlResult, error) {
	d, err := s.domainEngine()
	if err != nil {
		return DomainControlResult{}, err
	}
	if input.Action == "close" {
		return s.closeDomainKeys(d, input)
	}
	entry, err := d.entry(input)
	if err != nil {
		return DomainControlResult{}, err
	}
	switch input.Action {
	case "adopt":
		return d.adopt(entry)
	case "receive":
		return d.receive(entry)
	case "validate":
		return s.validateDomainLease(d, entry, input)
	case "handoff":
		return s.handoffDomain(ctx, d, entry, input)
	case "finish":
		return s.finishDomain(d, entry, input)
	}
	return DomainControlResult{}, fmt.Errorf("invalid native lease control")
}
func (d *domainEngine) adopt(entry *domainEntry) (DomainControlResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if entry.finished || entry.disposition != "" || entry.executing {
		return DomainControlResult{}, fmt.Errorf("native exchange unavailable")
	}
	entry.adopted = true
	return DomainControlResult{Value: map[string]bool{"adopted": true}}, nil
}
func (d *domainEngine) receive(entry *domainEntry) (DomainControlResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !entry.adopted || entry.finished || entry.disposition != "" || entry.executing {
		return DomainControlResult{}, fmt.Errorf("native receive requires active adopted lease")
	}
	result := DomainReceived{Body: append([]byte(nil), entry.body...), ResponseHash: entry.responseHash, Lease: entry.lease, Pair: entry.pair}
	return DomainControlResult{Value: result}, nil
}
func (s *Server) validateDomainLease(d *domainEngine, entry *domainEntry, input DomainControl) (DomainControlResult, error) {
	d.mu.Lock()
	active := d.activeLocked(entry)
	d.mu.Unlock()
	if !active || input.LeaseBinding == nil || input.Intent == nil || !domainEqual(*input.LeaseBinding, entry.lease) || !domainEqual(*input.Intent, entry.intent) || input.PrincipalID != entry.lease.PrincipalID || input.SessionID != entry.lease.SessionID {
		return DomainControlResult{}, fmt.Errorf("exact current lease binding denied")
	}
	until := math.Min(input.ValidUntil, entry.actor.ExpiresAt)
	if math.IsNaN(until) || math.IsInf(until, 0) || until <= domainNow() {
		return DomainControlResult{}, fmt.Errorf("finite native lease validity expired")
	}
	if err := s.authorizeDomainHandoffLocked(d, entry, entry.actor); err != nil {
		return DomainControlResult{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.activeLocked(entry) {
		return DomainControlResult{}, fmt.Errorf("native lease no longer active")
	}
	return DomainControlResult{Value: map[string]interface{}{"leaseBinding": entry.lease, "validUntil": until}}, nil
}
func (s *Server) handoffDomain(ctx context.Context, d *domainEngine, entry *domainEntry, input DomainControl) (DomainControlResult, error) {
	d.mu.Lock()
	active := d.activeLocked(entry)
	d.mu.Unlock()
	if !active {
		return DomainControlResult{}, fmt.Errorf("native handoff lease inactive/closed")
	}
	actor, err := d.verify(ctx, input.Proof, "handoff", entry.intent, &entry.lease)
	if err != nil {
		return DomainControlResult{}, err
	}
	if actor.PrincipalID != entry.lease.PrincipalID || actor.SessionID != entry.lease.SessionID {
		return DomainControlResult{}, fmt.Errorf("handoff actor mismatch")
	}
	if err = s.authorizeDomainHandoffLocked(d, entry, actor); err != nil {
		return DomainControlResult{}, err
	}
	id, err := newDomainID()
	if err != nil {
		return DomainControlResult{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.activeLocked(entry) || actor.ExpiresAt <= domainNow() {
		return DomainControlResult{}, fmt.Errorf("native handoff denied")
	}
	entry.permitID = id
	return DomainControlResult{Value: DomainPermit{d.epoch, entry.lease.LeaseID, id, entry.responseHash}}, nil
}
func (d *domainEngine) activeLocked(entry *domainEntry) bool {
	key := DomainGateKey{entry.lease.PrincipalID, entry.lease.SessionID, entry.lease.Scope}
	return entry.adopted && !entry.finished && entry.disposition == "" && !entry.executing && !d.closed[key]
}
func (s *Server) authorizeDomainHandoffLocked(d *domainEngine, entry *domainEntry, actor DomainVerified) error {
	d.mu.Lock()
	copy := *entry
	d.mu.Unlock()
	entry = &copy
	s.forestMutex.RLock()
	defer s.forestMutex.RUnlock()
	current, _, view, err := s.resolveDomainLocked(d, entry.input)
	if err != nil {
		return err
	}
	if !domainEqual(current, entry.intent) {
		return fmt.Errorf("native intent changed before handoff")
	}
	if err = d.authorizeIntentLocked(actor, view); err != nil {
		return err
	}
	if entry.receiptKey == "" {
		return nil
	}
	receipt, err := s.domainHandoffReceiptLocked(entry)
	if err != nil {
		return err
	}
	entry.actor = actor
	evaluation, err := newDomainEvaluation(current, view)
	if err != nil {
		return err
	}
	return authorizeStagedReplay(s.domainEvaluationAuthorizer(d, entry, evaluation), entry.owned.Binding, receipt)
}
func (s *Server) finishDomain(d *domainEngine, entry *domainEntry, input DomainControl) (DomainControlResult, error) {
	d.mu.Lock()
	if entry.executing || input.ResponseHash != entry.responseHash || (input.Disposition != "handed-off" && input.Disposition != "irrevocably-discarded") {
		d.mu.Unlock()
		return DomainControlResult{}, fmt.Errorf("native completion identity invalid")
	}
	if input.Disposition == "handed-off" && (!entry.adopted || entry.permitID == "" || input.PermitID != entry.permitID) {
		d.mu.Unlock()
		return DomainControlResult{}, fmt.Errorf("native handoff permit required")
	}
	if entry.disposition != "" && entry.disposition != input.Disposition {
		d.mu.Unlock()
		return DomainControlResult{}, fmt.Errorf("native completion disposition conflict")
	}
	entry.disposition = input.Disposition
	entry.body = nil
	key := entry.pendingKey
	d.mu.Unlock()
	if key != "" {
		if _, err := s.reconcileOwnedCommand(entry.owned.Binding.ScopeID, key); err != nil {
			return DomainControlResult{Value: map[string]bool{"completed": false}}, nil
		}
	}
	d.mu.Lock()
	entry.pendingKey = ""
	entry.finished = true
	d.mu.Unlock()
	return DomainControlResult{Value: map[string]bool{"completed": true}, Completed: true}, nil
}
