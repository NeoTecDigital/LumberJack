// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

type sourceProvisionCheck struct {
	ContractRevision string                  `json:"contractRevision"`
	Proof            string                  `json:"proof"`
	Phase            string                  `json:"phase"`
	Intent           PersonalProvisionIntent `json:"intent"`
	Lease            *ProvisionLeaseRef      `json:"lease"`
	Audience         string                  `json:"audience"`
}
type sourceProvisionVerified struct {
	ContractRevision        string                   `json:"contractRevision"`
	PrincipalID             string                   `json:"principalId"`
	Kind                    string                   `json:"kind"`
	SessionID               string                   `json:"sessionId"`
	Scope                   SourceScope              `json:"scope"`
	Account                 SourceAccount            `json:"account"`
	AccountRegistryRevision string                   `json:"accountRegistryRevision"`
	GrantRevision           string                   `json:"grantRevision"`
	Candidate               NativeProvisionCandidate `json:"candidate"`
	RequestID               string                   `json:"requestId"`
	IntentSHA256            string                   `json:"intentSha256"`
	AuthorityPolicyRevision string                   `json:"authorityPolicyRevision"`
	Intent                  PersonalProvisionIntent  `json:"intent"`
	Phase                   string                   `json:"phase"`
	Lease                   *ProvisionLeaseRef       `json:"lease"`
	ExpiresAt               float64                  `json:"expiresAt"`
	Audience                string                   `json:"audience"`
	Issuer                  string                   `json:"issuer"`
	ProofBinding            string                   `json:"proofBinding"`
}

// Private opaque one-use Core proof is verified over the actual HTTP callback.
// No network/callback call is permitted while forestMutex or p.mu is held.
func (p *personalSource) checkProvisionProof(ctx context.Context, proof, phase string, intent PersonalProvisionIntent, lease *ProvisionLeaseRef) (sourceProvisionVerified, error) {
	if !validProvisionPhase(phase, lease) || len(proof) > p.config.Bounds.MaxRequestBytes || !domainOpaqueProof.MatchString(proof) {
		return sourceProvisionVerified{}, sourceDenied()
	}
	check := sourceProvisionCheck{PersonalProvisionRevision, proof, phase, intent, lease, p.config.CoreCallback.Audience}
	body, err := CanonicalDomainJSON(check)
	if err != nil || len(body) > p.config.Bounds.MaxRequestBytes {
		return sourceProvisionVerified{}, sourceInvalid()
	}
	request, err := http.NewRequestWithContext(ctx, "POST", p.config.CoreCallback.Endpoint, bytes.NewReader(body))
	if err != nil {
		return sourceProvisionVerified{}, sourceUnavailable()
	}
	request.Header.Set("Authorization", "Bearer "+p.config.CoreCallback.ChannelToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return sourceProvisionVerified{}, sourceUnavailable()
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(p.config.Bounds.MaxResponseBytes)+1))
	if err != nil || response.StatusCode != http.StatusOK || len(raw) > p.config.Bounds.MaxResponseBytes {
		return sourceProvisionVerified{}, sourceDenied()
	}
	var actor sourceProvisionVerified
	bounds := p.config.Bounds
	bounds.MaxRequestBytes = bounds.MaxResponseBytes
	if sourceDecode(raw, &actor, bounds) != nil || !p.validProvisionProof(actor, check) {
		return sourceProvisionVerified{}, sourceDenied()
	}
	if ctx.Err() != nil {
		return sourceProvisionVerified{}, sourceUnavailable()
	}
	return actor, nil
}
func validProvisionPhase(phase string, lease *ProvisionLeaseRef) bool {
	if phase == "admission" {
		return lease == nil
	}
	return (phase == "execution" || phase == "disclosure") && lease != nil && lease.Phase == phase
}
func (p *personalSource) validProvisionProof(actor sourceProvisionVerified, check sourceProvisionCheck) bool {
	now := domainNow()
	if actor.ContractRevision != PersonalProvisionRevision || actor.Kind != "human" || domainWorkloadIdentity(actor.PrincipalID, actor.SessionID) || actor.PrincipalID != check.Intent.PrincipalID || actor.SessionID == "" || actor.Scope != check.Intent.Scope || !domainEqual(actor.Account, check.Intent.Account) {
		return false
	}
	if actor.Issuer != p.config.CoreCallback.Issuer || actor.Audience != check.Audience || actor.Phase != check.Phase || actor.ProofBinding != stagedHash([]byte(check.Proof)) {
		return false
	}
	if !domainEqual(actor.Intent, check.Intent) || !domainEqual(actor.Lease, check.Lease) || actor.IntentSHA256 != sourceCommandKey(check.Intent) {
		return false
	}
	if !domainFinite(actor.ExpiresAt) || actor.ExpiresAt <= now || actor.ExpiresAt > now+p.config.Bounds.LeaseSeconds || actor.AccountRegistryRevision == "" || actor.GrantRevision == "" || actor.AuthorityPolicyRevision == "" || actor.RequestID == "" {
		return false
	}
	return p.validProvisionCandidate(actor, check)
}
func (p *personalSource) validProvisionCandidate(actor sourceProvisionVerified, check sourceProvisionCheck) bool {
	c, i := actor.Candidate, check.Intent
	if c.RuntimeID != i.TargetRuntimeID || c.Epoch != p.epoch || c.CandidateRef != i.CandidateRef || c.CommandID != i.CommandID || c.PrincipalID != actor.PrincipalID || c.SessionID != actor.SessionID || !domainEqual(c.Account, actor.Account) {
		return false
	}
	if c.RootID != i.CandidateRootID || c.OwnerID != i.CandidateOwnerID || c.CommandSHA256 != i.CommandSHA256 || c.EnrollmentSHA256 != i.EnrollmentSHA256 || c.RequestID != actor.RequestID || c.RequestSHA256 != i.RequestSHA256 || c.IntentSHA256 != actor.IntentSHA256 || c.Phase != check.Phase {
		return false
	}
	if c.RegistryRevision == "" || c.SourceAuthorityRef != p.config.SourceAuthorityRef || c.PolicyRevision != p.config.SourcePolicyRevision || c.SourceRevision == "" {
		return false
	}
	now := domainNow()
	if !domainFinite(c.CheckedAt) || !domainFinite(c.ValidUntil) || c.CheckedAt > now || now-c.CheckedAt > p.config.Bounds.LeaseSeconds || c.ValidUntil <= now || actor.ExpiresAt > c.ValidUntil {
		return false
	}
	if c.State == "absent" {
		return c.Receipt == nil && i.ExpectedBindingRevision == nil && check.Phase != "disclosure"
	}
	return c.State == "committed_same_command" && c.Receipt != nil
}

type sourcePersonalAdmit struct {
	Command            json.RawMessage `json:"command"`
	CoreProvisionProof string          `json:"coreProvisionProof"`
}
type sourcePersonalExecute struct {
	Command            json.RawMessage   `json:"command"`
	LeaseRef           ProvisionLeaseRef `json:"leaseRef"`
	CoreProvisionProof string            `json:"coreProvisionProof"`
}
type sourcePersonalDisclose struct {
	LeaseRef           ProvisionLeaseRef `json:"leaseRef"`
	CoreProvisionProof string            `json:"coreProvisionProof"`
}
type sourcePersonalAdmissionResult struct {
	LeaseRef       SourceLeaseRef    `json:"leaseRef"`
	ExecutionLease ProvisionLeaseRef `json:"executionLease"`
}

func (p *personalSource) admitPersonal(ctx context.Context, request SourceEnvelope) (interface{}, error) {
	var input sourcePersonalAdmit
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	intent, err := personalIntentFromCommand(input.Command, p.config)
	if err != nil {
		return nil, err
	}
	entry, err := p.claimPersonal(intent, request.RequestID)
	if err != nil {
		return nil, err
	}
	defer p.releasePersonalBusy(entry)
	p.mu.Lock()
	admitted := entry.source != nil
	p.mu.Unlock()
	if admitted {
		return nil, sourceDenied()
	}
	actor, err := p.checkProvisionProof(ctx, input.CoreProvisionProof, "admission", intent, nil)
	if err != nil {
		return nil, err
	}
	if err = p.acceptPersonalActor(entry, actor); err != nil {
		return nil, err
	}
	admission, err := p.coordinator.reserveSession(enrollmentSessionKey{actor.PrincipalID, actor.SessionID}, p.config.Bounds.MaxLeases)
	if err != nil {
		return nil, err
	}
	defer admission.release()
	if _, err = p.personalCandidate(entry, "admission"); err != nil {
		return nil, err
	}
	return p.registerPersonalExecution(entry, input.Command, actor)
}
func (p *personalSource) executePersonal(ctx context.Context, request SourceEnvelope) (interface{}, error) {
	var input sourcePersonalExecute
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil || input.LeaseRef.Phase != "execution" {
		return nil, sourceInvalid()
	}
	intent, err := personalIntentFromCommand(input.Command, p.config)
	if err != nil {
		return nil, err
	}
	entry, err := p.claimPersonal(intent, request.RequestID)
	if err != nil {
		return nil, err
	}
	defer p.releasePersonalBusy(entry)
	if _, err = p.personalPhaseEvidence(entry, "execution", &input.LeaseRef); err != nil {
		return nil, err
	}
	actor, err := p.checkProvisionProof(ctx, input.CoreProvisionProof, "execution", intent, &input.LeaseRef)
	if err != nil {
		return nil, err
	}
	if err = p.acceptPersonalActor(entry, actor); err != nil {
		return nil, err
	}
	if err = p.persistPersonal(ctx, entry, actor); err != nil {
		return nil, err
	}
	p.mu.Lock()
	receipt := entry.candidate.Receipt
	p.mu.Unlock()
	if receipt == nil {
		return nil, sourceUnavailable()
	}
	return *receipt, nil // PRIVATE effect correlation only; disclosure proof still required.
}
func (p *personalSource) disclosePersonal(ctx context.Context, request SourceEnvelope) (interface{}, error) {
	var input sourcePersonalDisclose
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil || input.LeaseRef.Phase != "disclosure" {
		return nil, sourceInvalid()
	}
	entry, err := p.claimPersonalLease(input.LeaseRef, request.RequestID)
	if err != nil {
		return nil, err
	}
	defer p.releasePersonalBusy(entry)
	if _, err = p.personalPhaseEvidence(entry, "disclosure", &input.LeaseRef); err != nil {
		return nil, err
	}
	p.mu.Lock()
	intent := entry.intent
	p.mu.Unlock()
	actor, err := p.checkProvisionProof(ctx, input.CoreProvisionProof, "disclosure", intent, &input.LeaseRef)
	if err != nil {
		return nil, err
	}
	if err = p.acceptPersonalActor(entry, actor); err != nil {
		return nil, err
	}
	candidate, err := p.personalCandidate(entry, "disclosure")
	if err != nil {
		return nil, err
	}
	if candidate.State != "committed_same_command" || candidate.Receipt == nil || actor.ExpiresAt <= domainNow() {
		return nil, sourceDenied()
	}
	return *candidate.Receipt, nil
}
func (p *personalSource) claimPersonal(intent PersonalProvisionIntent, requestID string) (*personalProvisionEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.candidates[intent.CandidateRef]
	if !p.personalLiveLocked(entry) || entry.busy || entry.candidate.RequestID != requestID || !domainEqual(entry.intent, intent) {
		return nil, sourceDenied()
	}
	entry.busy = true
	return entry, nil
}
func (p *personalSource) claimPersonalLease(lease ProvisionLeaseRef, requestID string) (*personalProvisionEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.candidates[lease.CandidateRef]
	if !p.personalLiveLocked(entry) || entry.busy || entry.candidate.RequestID != requestID {
		return nil, sourceDenied()
	}
	stored, present := entry.phases[lease.Phase]
	if !present || !domainEqual(stored, lease) {
		return nil, sourceDenied()
	}
	entry.busy = true
	return entry, nil
}
func (p *personalSource) releasePersonalBusy(entry *personalProvisionEntry) {
	p.mu.Lock()
	entry.busy = false
	p.mu.Unlock()
}
func (p *personalSource) acceptPersonalActor(entry *personalProvisionEntry, actor sourceProvisionVerified) error {
	current, err := p.personalCandidate(entry, actor.Phase)
	if err != nil || !samePersonalCandidate(current, actor.Candidate) {
		return sourceDenied()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.personalLiveLocked(entry) || actor.PrincipalID != entry.actor.PrincipalID || actor.SessionID != entry.actor.SessionID || actor.RequestID != entry.candidate.RequestID || actor.GrantRevision != entry.grant.Revision || actor.ExpiresAt <= domainNow() {
		return sourceDenied()
	}
	if entry.verified != nil && (entry.verified.AccountRegistryRevision != actor.AccountRegistryRevision || entry.verified.AuthorityPolicyRevision != actor.AuthorityPolicyRevision || entry.verified.GrantRevision != actor.GrantRevision) {
		return sourceDenied()
	}
	entry.validUntil = min(entry.validUntil, actor.ExpiresAt)
	entry.verified = &actor
	return nil
}
func (p *personalSource) registerPersonalExecution(entry *personalProvisionEntry, command json.RawMessage, actor sourceProvisionVerified) (interface{}, error) {
	id, err := newDomainID()
	if err != nil {
		return nil, sourceUnavailable()
	}
	leaseID, err := newDomainID()
	if err != nil {
		return nil, sourceUnavailable()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.personalLiveLocked(entry) || entry.source != nil || len(p.entries)+len(p.candidates) >= p.config.Bounds.MaxLeases {
		return nil, sourceDenied()
	}
	c, i := entry.candidate, entry.intent
	owner := SourceOwnerRef{RuntimeID: c.RuntimeID, RootID: c.RootID, OwnerID: c.OwnerID}
	ref := SourceLeaseRef{p.epoch, p.config.HostID, id, c.RequestID, sourceCommandKey(owner), i.Request.PayloadSHA256, c.SourceRevision, nil, entry.validUntil}
	source := &personalSourceEntry{ref: ref, actor: entry.actor, grant: entry.grant, provision: entry, owner: owner}
	phase := ProvisionLeaseRef{p.epoch, leaseID, c.PrincipalID, c.SessionID, i.Account.AccountID, c.RuntimeID, c.CandidateRef, c.RootID, c.OwnerID, i.CommandSHA256, i.RequestSHA256, c.SourceRevision, c.RegistryRevision, "execution"}
	p.entries[id] = source
	entry.source, entry.originalCommand, entry.state = source, append([]byte(nil), command...), "admitted_no_effect"
	entry.phases["execution"] = phase
	return sourcePersonalAdmissionResult{ref, phase}, nil
}
func (p *personalSource) personalPhaseEvidence(entry *personalProvisionEntry, phase string, requested *ProvisionLeaseRef) (*sourceValidatedProvisionLease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.personalLiveLocked(entry) {
		return nil, sourceDenied()
	}
	stored, present := entry.phases[phase]
	if phase == "admission" {
		if requested != nil {
			return nil, sourceDenied()
		}
		return nil, nil
	}
	if !present || (requested != nil && !domainEqual(stored, *requested)) {
		return nil, sourceDenied()
	}
	if phase == "disclosure" && entry.state != "committed" {
		return nil, sourceDenied()
	}
	return &sourceValidatedProvisionLease{stored, entry.validUntil}, nil
}

// CheckedAt may refresh, but no immutable native fact or original deadline may.
func samePersonalCandidate(current, verified NativeProvisionCandidate) bool {
	if verified.CheckedAt > current.CheckedAt || verified.ValidUntil > current.ValidUntil {
		return false
	}
	current.CheckedAt, current.ValidUntil = verified.CheckedAt, verified.ValidUntil
	return domainEqual(current, verified)
}
