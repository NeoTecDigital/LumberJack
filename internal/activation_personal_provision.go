// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"time"
)

// Actual state populated only by real preparation/admission/paired effect.
// Request-supplied IDs can never allocate a lease or establish authority.
type personalProvisionEntry struct {
	actor           SourceActor
	grant           SourcePersonalGrant
	candidate       SourceProspectiveCandidate
	intent          PersonalProvisionIntent
	originalCommand json.RawMessage
	source          *personalSourceEntry
	write           *sourceWritePermit
	scope           *stagedScope
	pending         *stagedPending
	ledger          *core.PersonalBindingLedger
	snapshot        stateSnapshot
	durable         *stagedDurableStamp
	phases          map[string]ProvisionLeaseRef
	state           string
	validUntil      float64
	prepared        sourceProvisionPrepare
	verified        *sourceProvisionVerified
	busy            bool
	recovering      bool
}
type SourceProspectiveCandidate struct {
	CandidateRef            string                          `json:"candidateRef"`
	RootID                  string                          `json:"rootId"`
	OwnerID                 string                          `json:"ownerId"`
	RuntimeID               string                          `json:"runtimeId"`
	CommandID               string                          `json:"commandId"`
	PrincipalID             string                          `json:"principalId"`
	SessionID               string                          `json:"sessionId"`
	RequestID               string                          `json:"requestId"`
	RegistryRevision        string                          `json:"registryRevision"`
	SourceRevision          string                          `json:"sourceRevision"`
	PolicyRevision          string                          `json:"policyRevision"`
	ExpectedBindingRevision *string                         `json:"expectedBindingRevision"`
	State                   string                          `json:"state"`
	Receipt                 *NativePersonalProvisionReceipt `json:"receipt"`
	ValidUntil              float64                         `json:"validUntil"`
}

type sourceProvisionPrepare struct {
	CommandID               string              `json:"commandId"`
	PrincipalID             string              `json:"principalId"`
	Account                 SourceAccount       `json:"account"`
	EnrollmentReference     SourceEnrollment    `json:"enrollmentReference"`
	ExpectedBindingRevision *string             `json:"expectedBindingRevision"`
	Mode                    string              `json:"mode"`
	Actor                   SourceActor         `json:"actor"`
	Grant                   SourcePersonalGrant `json:"grant"`
	TargetRuntimeID         string              `json:"targetRuntimeId"`
	SourcePolicyRevision    string              `json:"sourcePolicyRevision"`
}
type sourceProvisionGuard struct {
	Mode              string                  `json:"mode"`
	Actor             SourceActor             `json:"actor"`
	Grant             SourcePersonalGrant     `json:"grant"`
	Intent            PersonalProvisionIntent `json:"intent"`
	Phase             string                  `json:"phase"`
	SourceLeaseRef    *SourceLeaseRef         `json:"sourceLeaseRef"`
	ProvisionLeaseRef *ProvisionLeaseRef      `json:"provisionLeaseRef"`
}
type sourceValidatedProvisionLease struct {
	Lease      ProvisionLeaseRef `json:"lease"`
	ValidUntil float64           `json:"validUntil"`
}
type sourceProvisionGuardResult struct {
	LeaseRef                SourceLeaseRef                 `json:"leaseRef"`
	Candidate               NativeProvisionCandidate       `json:"candidate"`
	ValidatedProvisionLease *sourceValidatedProvisionLease `json:"validatedProvisionLease"`
}

func personalScopeID(account string) string { return "lj.personal/v1:" + sourceCommandKey(account) }
func personalReceiptKey(principal, account, command string) string {
	return stagedCommandKey(stagedCommand{PrincipalID: principal, AccountID: account, ScopeID: personalScopeID(account), CommandID: command})
}
func (p *personalSource) provisionResolve(ctx context.Context, request SourceEnvelope) (interface{}, error) {
	var member struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal(request.Payload, &member) != nil {
		return nil, sourceInvalid()
	}
	if member.Mode == "prepare" {
		return p.preparePersonal(request)
	}
	if member.Mode == "guard" {
		return p.guardPersonal(ctx, request)
	}
	return nil, sourceInvalid()
}
func (p *personalSource) preparePersonal(request SourceEnvelope) (interface{}, error) {
	var input sourceProvisionPrepare
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	if !p.validPersonalPrepare(input, request.RequestID) {
		return nil, sourceDenied()
	}
	key := enrollmentSessionKey{input.Actor.PrincipalID, input.Actor.SessionID}
	admission, err := p.coordinator.reserveSession(key, p.config.Bounds.MaxLeases)
	if err != nil {
		return nil, err
	}
	defer admission.release()
	read, err := p.coordinator.beginRead(nil)
	if err != nil {
		return nil, err
	}
	defer read.release()
	p.server.forestMutex.RLock()
	defer p.server.forestMutex.RUnlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries)+len(p.candidates) >= p.config.Bounds.MaxLeases {
		return nil, sourceUnavailable()
	}
	entry, err := p.makePersonalCandidateLocked(input, request)
	if err != nil {
		return nil, err
	}
	p.candidates[entry.candidate.CandidateRef] = entry
	ref := entry.candidate.CandidateRef
	time.AfterFunc(time.Duration((entry.validUntil-domainNow())*float64(time.Second)), func() { p.expirePersonalPrepared(ref) })
	return entry.candidate, nil
}
func (p *personalSource) validPersonalPrepare(i sourceProvisionPrepare, requestID string) bool {
	if i.Mode != "prepare" || validateSourceActorGrant(i.Actor, i.Grant, requestID, p.config.Bounds) != nil || i.Actor.Evidence.Assurance != "aal2" {
		return false
	}
	if i.PrincipalID != i.Actor.PrincipalID || !domainEqual(i.Account, i.Grant.Account) || i.TargetRuntimeID != p.server.forest.ID || i.SourcePolicyRevision != p.config.SourcePolicyRevision {
		return false
	}
	if i.EnrollmentReference.Enrollment.Mode != "new" || i.EnrollmentReference.Enrollment.ExistingIdentityRef != nil || i.EnrollmentReference.Enrollment.ExpectedRevision != nil {
		return false
	}
	return validateStagedIdentifiers(p.config.StagedBounds, i.CommandID, i.PrincipalID, i.Account.AccountID, i.Account.SubjectRef.SubjectID, i.EnrollmentReference.CommandID, i.EnrollmentReference.Revision) == nil
}
func (p *personalSource) makePersonalCandidateLocked(input sourceProvisionPrepare, request SourceEnvelope) (*personalProvisionEntry, error) {
	ref, err := newDomainID()
	if err != nil {
		return nil, sourceUnavailable()
	}
	root, owner, registry, state, receipt, err := p.personalPreparationRefsLocked(input)
	if err != nil {
		return nil, err
	}
	revision := p.server.sourceForestRevisionLocked()
	until := min(request.ValidUntil, input.Actor.Evidence.ValidUntil, domainNow()+p.config.Bounds.LeaseSeconds)
	if revision == "" || until <= domainNow() {
		return nil, sourceUnavailable()
	}
	candidate := SourceProspectiveCandidate{ref, root, owner, p.server.forest.ID, input.CommandID, input.PrincipalID, input.Actor.SessionID, request.RequestID, registry, revision, p.config.SourcePolicyRevision, input.ExpectedBindingRevision, state, receipt, until}
	return &personalProvisionEntry{actor: input.Actor, grant: input.Grant, candidate: candidate, prepared: input, phases: map[string]ProvisionLeaseRef{}, state: "prepared_no_effect", validUntil: until}, nil
}
func (p *personalSource) personalPreparationRefsLocked(input sourceProvisionPrepare) (string, string, string, string, *NativePersonalProvisionReceipt, error) {
	ledger := p.server.forest.PersonalBindings
	if ledger != nil {
		if binding, present := ledger.Bindings[input.Account.AccountID]; present {
			return p.existingPersonalPreparationLocked(input, binding, ledger)
		}
		if len(ledger.Bindings) >= p.config.Bounds.MaxBindings || len(ledger.Receipts) >= p.config.Bounds.MaxBindings {
			return "", "", "", "", nil, sourceUnavailable()
		}
	}
	if input.ExpectedBindingRevision != nil {
		return "", "", "", "", nil, sourceDenied()
	}
	index, err := stagedForestIndex(p.server.forest)
	if err != nil {
		return "", "", "", "", nil, sourceUnavailable()
	}
	root, err := allocateEnrollmentID(index)
	if err != nil {
		return "", "", "", "", nil, err
	}
	owner, err := allocateEnrollmentID(index)
	if err != nil || owner == root || owner == input.PrincipalID || owner == input.Account.AccountID || owner == input.Account.SubjectRef.SubjectID {
		return "", "", "", "", nil, sourceUnavailable()
	}
	return root, owner, personalRegistryRevision(ledger), "absent", nil, nil
}
func personalRegistryRevision(ledger *core.PersonalBindingLedger) string {
	if ledger == nil {
		return "personal-registry/empty"
	}
	return ledger.Revision
}
func (p *personalSource) existingPersonalPreparationLocked(i sourceProvisionPrepare, b core.PersonalBindingRecord, l *core.PersonalBindingLedger) (string, string, string, string, *NativePersonalProvisionReceipt, error) {
	item, present := l.Receipts[personalReceiptKey(i.PrincipalID, i.Account.AccountID, i.CommandID)]
	if !present || b.PrincipalID != i.PrincipalID || b.OwnerKind != "new" || !domainEqual(b.Account, i.Account) || !domainEqual(b.Enrollment, i.EnrollmentReference) {
		return "", "", "", "", nil, sourceDenied()
	}
	r := item.Receipt
	if r.PrincipalID != i.PrincipalID || !domainEqual(r.OwnerRef, b.OwnerRef) || r.BindingRevision != b.BindingRevision || r.ContractRevision != PersonalSourceRevision || r.EnrollmentSHA256 != sourceCommandKey(i.EnrollmentReference) {
		return "", "", "", "", nil, sourceDenied()
	}
	if i.ExpectedBindingRevision != nil && *i.ExpectedBindingRevision != b.BindingRevision {
		return "", "", "", "", nil, sourceDenied()
	}
	return r.OwnerRef.RootID, r.OwnerRef.OwnerID, r.RegistryRevision, "committed_same_command", &r, nil
}
func (p *personalSource) guardPersonal(ctx context.Context, request SourceEnvelope) (interface{}, error) {
	var input sourceProvisionGuard
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	if input.Mode != "guard" || !validPersonalGuardPhase(input.Phase, input.ProvisionLeaseRef) {
		return nil, sourceDenied()
	}
	entry, err := p.personalIntentEntry(input, request.RequestID)
	if err != nil {
		return nil, err
	}
	if err = p.recoverPersonalWitness(ctx, entry); err != nil {
		return nil, err
	}
	guard, err := p.openPersonalGuard(entry, input, request)
	if err != nil {
		return nil, err
	}
	candidate, err := p.personalCandidate(entry, input.Phase)
	if err != nil {
		p.closeReadEntry(guard)
		return nil, err
	}
	validated, err := p.personalPhaseEvidence(entry, input.Phase, input.ProvisionLeaseRef)
	if err != nil {
		p.closeReadEntry(guard)
		return nil, err
	}
	return sourceProvisionGuardResult{guard.ref, candidate, validated}, nil
}
func (p *personalSource) personalIntentEntry(i sourceProvisionGuard, requestID string) (*personalProvisionEntry, error) {
	if validateSourceActorGrant(i.Actor, i.Grant, requestID, p.config.Bounds) != nil || i.Actor.Evidence.Assurance != "aal2" || validatePersonalIntent(i.Intent, p.config) != nil {
		return nil, sourceDenied()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.candidates[i.Intent.CandidateRef]
	if entry == nil || entry.state == "released" || entry.validUntil <= domainNow() || entry.candidate.RequestID != requestID || !sourceActorSame(entry.actor, i.Actor) || !domainEqual(entry.grant, i.Grant) || !personalIntentMatchesPrepared(i.Intent, entry) {
		return nil, sourceDenied()
	}
	if entry.intent.ContractRevision != "" && !domainEqual(entry.intent, i.Intent) {
		return nil, sourceDenied()
	}
	if entry.intent.ContractRevision == "" {
		entry.intent = i.Intent
	}
	return entry, nil
}
func personalIntentMatchesPrepared(i PersonalProvisionIntent, e *personalProvisionEntry) bool {
	p := e.prepared
	c := e.candidate
	return i.CommandID == p.CommandID && i.PrincipalID == p.PrincipalID && i.Scope == p.Grant.Scope && domainEqual(i.Account, p.Account) && domainEqual(i.Enrollment, p.EnrollmentReference) && i.TargetRuntimeID == c.RuntimeID && i.CandidateRootID == c.RootID && i.CandidateOwnerID == c.OwnerID && i.CandidateRef == c.CandidateRef && domainEqual(i.ExpectedBindingRevision, p.ExpectedBindingRevision) && i.SourcePolicyRevision == c.PolicyRevision
}
func (p *personalSource) personalCandidate(entry *personalProvisionEntry, phase string) (NativeProvisionCandidate, error) {
	p.server.forestMutex.RLock()
	defer p.server.forestMutex.RUnlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.personalLiveLocked(entry) || entry.intent.ContractRevision == "" {
		return NativeProvisionCandidate{}, sourceDenied()
	}
	if p.personalCurrentLocked(entry) != nil {
		return NativeProvisionCandidate{}, sourceDenied()
	}
	c, i := entry.candidate, entry.intent
	until := min(entry.validUntil, entry.actor.Evidence.ValidUntil)
	return NativeProvisionCandidate{c.RuntimeID, p.epoch, c.CandidateRef, c.CommandID, c.PrincipalID, c.SessionID, i.Account, c.RootID, c.OwnerID, c.RegistryRevision, i.CommandSHA256, i.EnrollmentSHA256, p.config.SourceAuthorityRef, c.SourceRevision, c.PolicyRevision, c.RequestID, i.RequestSHA256, sourceCommandKey(i), phase, domainNow(), until, c.State, c.Receipt}, nil
}
func (p *personalSource) personalLiveLocked(entry *personalProvisionEntry) bool {
	return entry != nil && entry.state != "released" && entry.validUntil > domainNow() && !p.coordinator.sessionFenced(enrollmentSessionKey{entry.actor.PrincipalID, entry.actor.SessionID})
}
func (p *personalSource) personalCurrentLocked(e *personalProvisionEntry) error {
	ledger := p.server.forest.PersonalBindings
	if e.candidate.State == "absent" {
		if ledger != nil && ledger.Bindings[e.grant.Account.AccountID].BindingRevision != "" {
			return sourceDenied()
		}
		if personalRegistryRevision(ledger) != e.candidate.RegistryRevision || p.server.sourceForestRevisionLocked() != e.candidate.SourceRevision {
			return sourceDenied()
		}
		return nil
	}
	if ledger == nil || e.candidate.Receipt == nil {
		return sourceDenied()
	}
	item, present := ledger.Receipts[personalReceiptKey(e.actor.PrincipalID, e.grant.Account.AccountID, e.candidate.CommandID)]
	binding, presentBinding := ledger.Bindings[e.grant.Account.AccountID]
	if !present || !presentBinding || item.Receipt.CommandSHA256 != e.intent.CommandSHA256 || !domainEqual(item.Receipt, *e.candidate.Receipt) || !domainEqual(item.Payload, personalStablePayload(e.intent)) {
		return sourceDenied()
	}
	index, err := stagedForestIndex(p.server.forest)
	if err != nil || p.actualPersonalRootLocked(binding, index) != nil || binding.PrincipalID != e.actor.PrincipalID || !domainEqual(binding.Account, e.grant.Account) {
		return sourceDenied()
	}
	return p.personalPairWitnessLocked(e)
}
func (p *personalSource) matchPersonalGuard(ref SourceLeaseRef, e *personalProvisionEntry, requestID string) error {
	guard, err := p.lookupEntry(ref, requestID)
	if err != nil || !guard.guard || guard.provision != e || guard.read == nil || guard.read.recheck() != nil {
		return sourceDenied()
	}
	return nil
}

func (p *personalSource) openPersonalGuard(entry *personalProvisionEntry, input sourceProvisionGuard, request SourceEnvelope) (*personalSourceEntry, error) {
	if input.SourceLeaseRef != nil {
		if p.matchPersonalGuard(*input.SourceLeaseRef, entry, request.RequestID) != nil {
			return nil, sourceDenied()
		}
		return p.lookupEntry(*input.SourceLeaseRef, request.RequestID)
	}
	p.mu.Lock()
	borrow := entry.write
	if borrow != nil && !borrow.owns(p.coordinator) {
		borrow = nil
	}
	until := entry.validUntil
	owner := entry.candidate
	p.mu.Unlock()
	guard, err := p.newReadEntry(request, owner, input.Intent, min(input.Actor.Evidence.ValidUntil, until), borrow)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	guard.actor, guard.grant, guard.provision, guard.guard = input.Actor, input.Grant, entry, true
	guard.owner = SourceOwnerRef{entry.candidate.RuntimeID, entry.candidate.RootID, entry.candidate.OwnerID}
	p.mu.Unlock()
	return guard, nil
}

func (p *personalSource) persistPersonal(ctx context.Context, e *personalProvisionEntry, actor sourceProvisionVerified) error {
	command := personalStagedCommand(e.intent, personalScopeID(e.intent.Account.AccountID))
	permit, err := p.coordinator.beginWrite(ctx, sourceCommandKey(command))
	if err != nil {
		return err
	}
	p.mu.Lock()
	e.write = permit
	p.mu.Unlock()
	p.server.forestMutex.Lock()
	p.mu.Lock()
	if !p.personalLiveLocked(e) || actor.ExpiresAt <= domainNow() {
		p.mu.Unlock()
		p.server.forestMutex.Unlock()
		permit.noEffect(true)
		return sourceDenied()
	}
	replayed := e.candidate.State == "committed_same_command"
	p.mu.Unlock()
	if replayed {
		err = p.personalCurrentLocked(e)
	} else {
		err = p.buildPersonalPendingLocked(e, actor)
	}
	p.server.forestMutex.Unlock()
	if err != nil {
		permit.noEffect(true)
		return err
	}
	if replayed {
		permit.finish(true, false)
		return p.completePersonalCommit(e, nil)
	}
	return p.commitPersonalPending(e, actor, permit)
}
func (p *personalSource) markPersonalUnknown(e *personalProvisionEntry, permit *sourceWritePermit) {
	p.mu.Lock()
	e.state = "unknown"
	if e.source != nil {
		e.source.unknown = true
	}
	p.mu.Unlock()
	permit.finish(false, true)
}
func (p *personalSource) completePersonalCommit(e *personalProvisionEntry, stamp *stagedDurableStamp) error {
	id, err := newDomainID()
	if err != nil {
		return sourceUnavailable()
	}
	p.server.forestMutex.RLock()
	defer p.server.forestMutex.RUnlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	ledger := p.server.forest.PersonalBindings
	if ledger == nil {
		return sourceUnavailable()
	}
	item, present := ledger.Receipts[personalReceiptKey(e.actor.PrincipalID, e.grant.Account.AccountID, e.candidate.CommandID)]
	if !present || item.Receipt.CommandSHA256 != e.intent.CommandSHA256 {
		return sourceDenied()
	}
	e.write = nil
	e.durable = stamp
	e.pending = nil
	e.state = "committed"
	e.candidate.State = "committed_same_command"
	r := item.Receipt
	e.candidate.Receipt = &r
	e.candidate.RegistryRevision = r.RegistryRevision
	e.candidate.SourceRevision = p.server.sourceForestRevisionLocked()
	if e.source != nil {
		e.source.unknown = false
	}
	c, i := e.candidate, e.intent
	e.phases["disclosure"] = ProvisionLeaseRef{p.epoch, id, c.PrincipalID, c.SessionID, i.Account.AccountID, c.RuntimeID, c.CandidateRef, c.RootID, c.OwnerID, i.CommandSHA256, i.RequestSHA256, c.SourceRevision, c.RegistryRevision, "disclosure"}
	return p.personalCurrentLocked(e)
}
func validPersonalGuardPhase(phase string, lease *ProvisionLeaseRef) bool {
	if lease != nil {
		return validProvisionPhase(phase, lease)
	}
	return phase == "admission" || phase == "execution" || phase == "disclosure"
}
