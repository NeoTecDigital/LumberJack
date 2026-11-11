// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

type personalSource struct {
	mu               sync.Mutex
	server           *Server
	config           PersonalSourceConfig
	epoch            string
	client           *http.Client
	coordinator      *sourceCoordinator
	entries          map[string]*personalSourceEntry
	controls         map[string]sourceControlEntry
	candidates       map[string]*personalProvisionEntry
	snapshots        map[string]SourceRootSnapshot
	subjectSnapshots map[string]canonicalRootSnapshotEntry
	onComplete       func(string)
}
type personalSourceEntry struct {
	canonical       *canonicalSourceEntry
	originalSHA     string
	canonicalFamily bool
	ref             SourceLeaseRef
	read            *sourceReadPermit
	actor           SourceActor
	grant           SourcePersonalGrant
	intent          *PersonalSourceIntent
	record          *SourceAssociationRecord
	subject         SourceSubjectEvidence
	purpose         string
	consentRef      string
	binding         *SourceOwnerBinding
	decision        *SourceResourceDecision
	provision       *personalProvisionEntry
	guard           bool
	closed          bool
	unknown         bool
	owner           SourceOwnerRef
}
type sourceControlEntry struct {
	ref     SourceControlRef
	key     string
	ownerID string
}
type SourceControlRef struct {
	ControlRef string  `json:"controlRef"`
	Epoch      string  `json:"epoch"`
	ValidUntil float64 `json:"validUntil"`
}

// This constructor never acts as Handle.actor, a native admin or systemDefault.
func (s *Server) ConfigurePersonalSource(config PersonalSourceConfig) (map[string]interface{}, error) {
	if err := s.refuseWholeStateWriterUnderTier("the personal source"); err != nil {
		return nil, err
	}
	s.sourceFence().requireFencing()
	raw, err := CanonicalDomainJSON(config)
	if err != nil || validatePersonalSourceConfig(config) != nil {
		return nil, sourceInvalid()
	}
	if sourceDecode(raw, &config, config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	client, err := sourceCallbackClient(config)
	if err != nil {
		return nil, err
	}
	epoch, err := newDomainID()
	if err != nil {
		return nil, sourceUnavailable()
	}
	c := s.sourceFence()
	permit, err := c.beginWrite(context.Background(), "source-configure")
	if err != nil {
		return nil, err
	}
	defer permit.finish(true, false)
	if s.personalSource.Load() != nil {
		return nil, sourceDenied()
	}
	if err = s.installPersonalSource(config, epoch, client, c); err != nil {
		return nil, err
	}

	return map[string]interface{}{"configured": true, "epoch": epoch, "maxLeases": config.Bounds.MaxLeases}, nil
}
func (s *Server) installPersonalSource(config PersonalSourceConfig, epoch string, client *http.Client, c *sourceCoordinator) error {
	p := &personalSource{server: s, config: config, epoch: epoch, client: client, coordinator: c,
		entries: map[string]*personalSourceEntry{}, controls: map[string]sourceControlEntry{}, candidates: map[string]*personalProvisionEntry{}, snapshots: map[string]SourceRootSnapshot{}}
	s.forestMutex.Lock()
	if s.stagedScopes == nil {
		s.stagedScopes = map[string]*stagedScope{}
	}
	err := p.validateLedgerLocked()
	s.forestMutex.Unlock()
	if err != nil {
		return err
	}
	if err = c.setSessionLimit(config.Bounds.MaxLeases); err != nil {
		return err
	}
	c.mu.Lock()
	c.timeout = time.Duration(config.Bounds.RequestSeconds * float64(time.Second))
	c.mu.Unlock()
	if !s.personalSource.CompareAndSwap(nil, p) {
		return sourceDenied()
	}
	return nil
}
func sourceCallbackClient(config PersonalSourceConfig) (*http.Client, error) {
	u, err := url.Parse(config.CoreCallback.Endpoint)
	if err != nil || u.Host == "" || u.Path == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return nil, sourceInvalid()
	}
	if u.Scheme != "https" {
		ip, e := netip.ParseAddr(u.Hostname())
		port, p := strconv.Atoi(u.Port())
		if u.Scheme != "http" || e != nil || !ip.IsLoopback() || ip.Zone() != "" || p != nil || port < 1024 || port > 65535 || u.RawPath != "" {
			return nil, sourceInvalid()
		}
	}
	timeout := time.Duration(config.Bounds.RequestSeconds * float64(time.Second))
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: timeout}).DialContext, TLSHandshakeTimeout: timeout, DisableKeepAlives: true}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func (p *personalSource) validateEnvelope(request SourceEnvelope) error {
	if request.ContractRevision == NativeCanonicalRevision && p.server.nativeControl.Load() == nil {
		return sourceUnavailable()
	}
	if (request.ContractRevision != PersonalSourceRevision && request.ContractRevision != NativeCanonicalRevision) || request.Epoch != p.epoch || request.HostID != p.config.HostID || subtle.ConstantTimeCompare([]byte(request.ChannelToken), []byte(p.config.ControlToken)) != 1 {
		return sourceDenied()
	}
	if !domainFinite(request.ValidUntil) || request.ValidUntil <= domainNow() || request.ValidUntil > domainNow()+p.config.Bounds.RequestSeconds {
		return sourceDenied()
	}
	return nil
}
func (p *personalSource) validateLedgerLocked() error {
	l := p.server.forest.PersonalBindings
	if l == nil {
		return nil
	}
	if l.Revision == "" || l.Bindings == nil || l.Consents == nil || l.Receipts == nil || len(l.Bindings) > p.config.Bounds.MaxBindings || len(l.Consents) > p.config.Bounds.MaxSources || len(l.Receipts) > p.config.Bounds.MaxBindings {
		return sourceUnavailable()
	}
	index, err := stagedForestIndex(p.server.forest)
	if err != nil {
		return sourceUnavailable()
	}
	for key, binding := range l.Bindings {
		if key != binding.Account.AccountID || binding.OwnerRef.RuntimeID != p.server.forest.ID || binding.BindingRevision == "" || binding.AccountRegistryRevision == "" {
			return sourceUnavailable()
		}
		if err = p.actualPersonalRootLocked(binding, index); err != nil {
			return err
		}
	}
	return p.validateMappedLedgerLocked(index)
}
func (p *personalSource) actualPersonalRootLocked(binding core.PersonalBindingRecord, index map[string]*core.Node) error {
	root := index[binding.OwnerRef.RootID]
	if root == nil || root == p.server.forest || root.CreatedBy != binding.OwnerRef.OwnerID || root.Metadata["personal_owner"] != binding.OwnerRef.OwnerID || root.Kind != "workspace" || !root.CheckPermission(binding.OwnerRef.OwnerID, core.AdminPermission) {
		return sourceDenied()
	}
	if p.server.forest.Children[root.ID] != root || len(root.Parents) != 1 || root.Parents[p.server.forest.ID] != p.server.forest.Name {
		return sourceDenied()
	}
	if binding.OwnerKind != "existing" && binding.OwnerKind != "new" {
		return sourceDenied()
	}
	return nil
}
func (p *personalSource) lookupEntry(ref SourceLeaseRef, requestID string) (*personalSourceEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.entries[ref.LeaseID]
	if entry == nil || entry.closed || entry.unknown || !domainEqual(entry.ref, ref) || ref.Epoch != p.epoch || ref.HostID != p.config.HostID || ref.RequestID != requestID || ref.ValidUntil <= domainNow() {
		return nil, sourceDenied()
	}
	return entry, nil
}
func (p *personalSource) newReadEntry(request SourceEnvelope, owner interface{}, payload interface{}, until float64, borrow *sourceWritePermit) (*personalSourceEntry, error) {
	read, err := p.coordinator.beginRead(borrow)
	if err != nil {
		return nil, err
	}
	id, err := newDomainID()
	if err != nil {
		read.release()
		return nil, sourceUnavailable()
	}
	revision := p.server.sourceForestRevision()
	if revision == "" {
		read.release()
		return nil, sourceUnavailable()
	}
	ref := SourceLeaseRef{p.epoch, p.config.HostID, id, request.RequestID, sourceCommandKey(owner), sourceCommandKey(payload), revision, nil, min(until, request.ValidUntil, domainNow()+p.config.Bounds.LeaseSeconds)}
	entry := &personalSourceEntry{ref: ref, read: read, originalSHA: stagedHash(request.Payload), canonicalFamily: request.ContractRevision == NativeCanonicalRevision}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries)+len(p.candidates) >= p.config.Bounds.MaxLeases || ref.ValidUntil <= domainNow() {
		read.release()
		return nil, sourceUnavailable()
	}
	p.entries[id] = entry
	time.AfterFunc(time.Duration((ref.ValidUntil-domainNow())*float64(time.Second)), func() { p.closeReadEntry(entry) })
	return entry, nil
}

// Actual embedded owner supplies only accounting, not actor/permission state.
func (s *Server) SetPersonalSourceCompletion(epoch string, complete func(string)) error {
	p := s.personalSource.Load()
	if p == nil || epoch != p.epoch || complete == nil {
		return sourceDenied()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.onComplete != nil {
		return sourceDenied()
	}
	p.onComplete = complete
	return nil
}
func (s *Server) PersonalSourceLeaseActive(epoch, id string) bool {
	p := s.personalSource.Load()
	if p == nil || p.epoch != epoch {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := p.entries[id]
	return entry != nil && !entry.closed
}
func sourceCanonicalCopy(value interface{}, target interface{}) error {
	raw, err := CanonicalDomainJSON(value)
	if err != nil || json.Unmarshal(raw, target) != nil {
		return sourceUnavailable()
	}
	return nil
}

type sourceBindingOpen struct {
	Actor  SourceActor          `json:"actor"`
	Grant  SourcePersonalGrant  `json:"grant"`
	Intent PersonalSourceIntent `json:"intent"`
}
type sourceBindingRecheck struct {
	LeaseRef SourceLeaseRef       `json:"leaseRef"`
	Actor    SourceActor          `json:"actor"`
	Grant    SourcePersonalGrant  `json:"grant"`
	Intent   PersonalSourceIntent `json:"intent"`
}
type sourceBindingResult struct {
	LeaseRef SourceLeaseRef     `json:"leaseRef"`
	Binding  SourceOwnerBinding `json:"binding"`
}

func (p *personalSource) bindingOpen(request SourceEnvelope) (interface{}, error) {
	var input sourceBindingOpen
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	if validateSourceActorGrant(input.Actor, input.Grant, request.RequestID, p.config.Bounds) != nil {
		return nil, sourceDenied()
	}
	admission, err := p.coordinator.reserveSession(enrollmentSessionKey{input.Actor.PrincipalID, input.Actor.SessionID}, p.config.Bounds.MaxLeases)
	if err != nil {
		return nil, err
	}
	defer admission.release()
	entry, err := p.newReadEntry(request, input.Intent.OwnerRef, input.Intent, input.Actor.Evidence.ValidUntil, nil)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	entry.actor, entry.grant, entry.intent = input.Actor, input.Grant, &input.Intent
	p.mu.Unlock()
	p.server.forestMutex.RLock()
	binding, err := p.currentBindingLocked(entry)
	p.server.forestMutex.RUnlock()
	if err != nil {
		p.closeReadEntry(entry)
		return nil, err
	}
	p.mu.Lock()
	entry.binding = &binding
	entry.owner = binding.OwnerRef
	p.mu.Unlock()
	return sourceBindingResult{entry.ref, binding}, nil
}
func (p *personalSource) currentBindingLocked(entry *personalSourceEntry) (SourceOwnerBinding, error) {
	l := p.server.forest.PersonalBindings
	if l == nil || entry.intent == nil || entry.read.recheck() != nil {
		return SourceOwnerBinding{}, sourceDenied()
	}
	record, present := l.Bindings[entry.grant.Account.AccountID]
	if entry.canonicalFamily {
		record, present = p.mappedBindingLocked(entry)
	}
	if !present || record.PrincipalID != entry.actor.PrincipalID || !domainEqual(record.Account, entry.grant.Account) {
		return SourceOwnerBinding{}, sourceDenied()
	}
	index, err := stagedForestIndex(p.server.forest)
	if err != nil || p.actualPersonalRootLocked(record, index) != nil {
		return SourceOwnerBinding{}, sourceDenied()
	}
	if !domainEqual(entry.intent.OwnerRef, record.OwnerRef) || entry.intent.BindingRevision != record.BindingRevision || entry.intent.Scope != entry.grant.Scope {
		return SourceOwnerBinding{}, sourceDenied()
	}
	if record.OwnerKind == "existing" && !p.existingConsentCurrentLocked(record, entry.actor.Evidence, l) {
		return SourceOwnerBinding{}, sourceDenied()
	}
	if record.OwnerKind == "new" && !personalNewReceiptCurrent(record, l) {
		return SourceOwnerBinding{}, sourceDenied()
	}
	until := min(entry.ref.ValidUntil, entry.actor.Evidence.ValidUntil)
	if until <= domainNow() || p.coordinator.sessionFenced(enrollmentSessionKey{entry.actor.PrincipalID, entry.actor.SessionID}) {
		return SourceOwnerBinding{}, sourceDenied()
	}
	return SourceOwnerBinding{record.PrincipalID, entry.actor.SessionID, record.Account, record.OwnerRef, record.BindingRevision, record.AccountRegistryRevision, record.Enrollment, record.AssociationID, record.AssociationRevision, p.config.SourceAuthorityRef, entry.ref.SourceRevision, p.config.SourcePolicyRevision, entry.ref.RequestID, sourceCommandKey(*entry.intent), domainNow(), until}, nil
}
func (p *personalSource) existingConsentCurrentLocked(record core.PersonalBindingRecord, subject SourceSubjectEvidence, l *core.PersonalBindingLedger) bool {
	if record.ConsentRef == nil || record.AssociationID == nil || record.AssociationRevision == nil {
		return false
	}
	consent, present := l.Consents[*record.ConsentRef]
	return present && consent.State == "active" && consent.Issuer == subject.Issuer && consent.Subject == subject.Subject && consent.NativeOwnerID == record.OwnerRef.OwnerID && consent.RootID == record.OwnerRef.RootID && consent.MappingRef != ""
}
func personalNewReceiptCurrent(record core.PersonalBindingRecord, l *core.PersonalBindingLedger) bool {
	if record.Enrollment.Enrollment.Mode != "new" || record.Enrollment.Enrollment.ExistingIdentityRef != nil || record.ConsentRef != nil || record.AssociationID != nil {
		return false
	}
	count := 0
	for _, item := range l.Receipts {
		r := item.Receipt
		if r.PrincipalID == record.PrincipalID && domainEqual(r.Account, record.Account) && domainEqual(r.OwnerRef, record.OwnerRef) && r.BindingRevision == record.BindingRevision && r.RegistryRevision != "" && r.EnrollmentSHA256 == sourceCommandKey(record.Enrollment) && r.ContractRevision == PersonalSourceRevision && r.Effect == "applied" {
			count++
		}
	}
	return count == 1
}
func (p *personalSource) bindingRecheck(request SourceEnvelope) (interface{}, error) {
	var input sourceBindingRecheck
	if sourceDecode(request.Payload, &input, p.config.Bounds) != nil {
		return nil, sourceInvalid()
	}
	entry, err := p.lookupEntry(input.LeaseRef, request.RequestID)
	if err != nil || !sourceActorSame(entry.actor, input.Actor) || !domainEqual(entry.grant, input.Grant) || entry.intent == nil || !domainEqual(*entry.intent, input.Intent) || entry.binding == nil {
		return nil, sourceDenied()
	}
	if validateSourceActorGrant(input.Actor, input.Grant, request.RequestID, p.config.Bounds) != nil {
		return nil, sourceDenied()
	}
	p.server.forestMutex.RLock()
	local := *entry
	local.actor = input.Actor
	binding, err := p.currentBindingLocked(&local)
	p.server.forestMutex.RUnlock()
	if err != nil {
		return nil, err
	}
	return sourceBindingResult{entry.ref, binding}, nil
}
