// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

type sourceControlCapture struct {
	NativeControlCredential string `json:"nativeControlCredential"`
}
type sourceConsentEstablish struct {
	CommandID               string                `json:"commandId"`
	ControlRef              string                `json:"controlRef"`
	SupabaseEvidence        SourceSubjectEvidence `json:"supabaseEvidence"`
	CanonicalMappingRef     string                `json:"canonicalMappingRef"`
	RootID                  string                `json:"rootId"`
	OwnerID                 string                `json:"ownerId"`
	ExpectedConsentRevision *string               `json:"expectedConsentRevision"`
}
type sourceConsentRevoke struct {
	CommandID               string `json:"commandId"`
	ControlRef              string `json:"controlRef"`
	ConsentRef              string `json:"consentRef"`
	ExpectedConsentRevision string `json:"expectedConsentRevision"`
}
type sourceConsentReceipt struct {
	CommandID       string `json:"commandId"`
	ConsentRef      string `json:"consentRef"`
	ConsentRevision string `json:"consentRevision"`
	SourceRevision  string `json:"sourceRevision"`
	Effect          string `json:"effect"`
}

func (p *personalSource) captureControl(request SourceEnvelope) (interface{}, error) {
	var input sourceControlCapture
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	if len(p.server.jwtConfig.SecretKey) == 0 {
		return nil, sourceUnavailable()
	}
	key := p.server.sessionKeyFromBearer(input.NativeControlCredential)
	if !strings.HasPrefix(input.NativeControlCredential, "ms_") {
		claims, refusal := p.server.legacySessionClaims(input.NativeControlCredential)
		if refusal != "" || claims == nil || claims.SessionID != key {
			return nil, sourceDenied()
		}
	}
	session, valid := p.server.registeredSession(key)
	if !valid || key == "" {
		return nil, sourceDenied()
	}
	id, err := newDomainID()
	if err != nil {
		return nil, sourceUnavailable()
	}
	ref := SourceControlRef{id, p.epoch, min(float64(applicationSessionDeadline(session)), request.ValidUntil, domainNow()+p.config.Bounds.LeaseSeconds)}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneExpiredControlsLocked()
	if len(p.controls) >= p.config.Bounds.MaxSources || ref.ValidUntil <= domainNow() {
		return nil, sourceUnavailable()
	}
	p.controls[id] = sourceControlEntry{ref, key, session.UserID}
	return ref, nil
}
func (p *personalSource) currentControlLocked(id string) (sourceControlEntry, error) {
	p.mu.Lock()
	held, present := p.controls[id]
	p.mu.Unlock()
	if !present || held.ref.Epoch != p.epoch || held.ref.ValidUntil <= domainNow() {
		return sourceControlEntry{}, sourceDenied()
	}
	session, valid := p.server.registeredSessionLocked(held.key, time.Now().Unix())
	if !valid || session.UserID != held.ownerID {
		return sourceControlEntry{}, sourceDenied()
	}
	return held, nil
}

// A mapping ref is not authority. No sealed current canonical mapping producer
// exists in the frozen dependencies: do not infer it from email/IDs/native tags.
func (p *personalSource) establishConsent(request SourceEnvelope) (interface{}, error) {
	var input sourceConsentEstablish
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	return nil, sourceUnavailable()
}
func (p *personalSource) revokeConsent(ctx context.Context, request SourceEnvelope) (interface{}, error) {
	var input sourceConsentRevoke
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	permit, err := p.coordinator.beginWrite(ctx, "consent-revoke/"+sourceCommandKey(input))
	if err != nil {
		return nil, err
	}
	p.server.forestMutex.Lock()
	before := p.server.sourceForestRevisionLocked()
	receipt, snapshot, err := p.revokeConsentLocked(request, input)
	unchanged := before != "" && before == p.server.sourceForestRevisionLocked()
	p.server.forestMutex.Unlock()
	if err != nil {
		permit.noEffect(unchanged)
		return nil, err
	}
	if err = p.server.commitState(snapshot); err != nil {
		permit.finish(false, true)
		return nil, sourceUnavailable()
	}
	permit.finish(true, true)
	return receipt, nil
}
func (p *personalSource) revokeConsentLocked(request SourceEnvelope, input sourceConsentRevoke) (sourceConsentReceipt, stateSnapshot, error) {
	held, err := p.currentControlLocked(input.ControlRef)
	if err != nil {
		return sourceConsentReceipt{}, stateSnapshot{}, err
	}
	ledger := p.server.forest.PersonalBindings
	if ledger == nil {
		return sourceConsentReceipt{}, stateSnapshot{}, sourceDenied()
	}
	consent, present := ledger.Consents[input.ConsentRef]
	if !present || consent.NativeOwnerID != held.ownerID {
		return sourceConsentReceipt{}, stateSnapshot{}, sourceDenied()
	}
	if consent.CommandID == input.CommandID && consent.CommandSHA256 == sourceCommandKey(input) && consent.State == "revoked" {
		snapshot, e := p.server.encodeSnapshotLocked(p.server.statePath(), true)
		return sourceConsentReceipt{input.CommandID, consent.ConsentRef, consent.Revision, p.server.sourceForestRevisionLocked(), "unchanged"}, snapshot, e
	}
	if consent.Revision != input.ExpectedConsentRevision || consent.State != "active" {
		return sourceConsentReceipt{}, stateSnapshot{}, sourceDenied()
	}
	var copy core.PersonalBindingLedger
	if sourceCanonicalCopy(ledger, &copy) != nil {
		return sourceConsentReceipt{}, stateSnapshot{}, sourceUnavailable()
	}
	consent.State, consent.CommandID, consent.CommandSHA256 = "revoked", input.CommandID, sourceCommandKey(input)
	consent.Revision = sourceCommandKey(consent)
	copy.Consents[input.ConsentRef] = consent
	copy.Revision = sourceCommandKey(copy)
	p.server.forest.PersonalBindings = &copy
	snapshot, e := p.server.encodeSnapshotLocked(p.server.statePath(), true)
	return sourceConsentReceipt{input.CommandID, consent.ConsentRef, consent.Revision, p.server.sourceForestRevisionLocked(), "applied"}, snapshot, e
}

func (p *personalSource) pruneExpiredControlsLocked() {
	now := domainNow()
	for id, entry := range p.controls {
		if entry.ref.ValidUntil <= now {
			delete(p.controls, id)
		}
	}
}
