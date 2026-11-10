// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"crypto/sha256"
	"fmt"
)

type coownerCurrentState struct {
	ScopeRevision      string  `json:"scopeRevision"`
	State              string  `json:"state"`
	OwnerGrantRevision *string `json:"ownerGrantRevision"`
	GrantCommandID     *string `json:"grantCommandId"`
	GrantFingerprint   *string `json:"grantFingerprint"`
}

type coownerCompletion struct {
	Effect           string `json:"effect"`
	OriginalExchange string `json:"originalExchange"`
}

type coownerInspection struct {
	ContractRevision        string                 `json:"contractRevision"`
	Mode                    string                 `json:"mode"`
	RequestID               string                 `json:"requestId"`
	Scope                   DomainScope            `json:"scope"`
	InspectionFingerprint   string                 `json:"inspectionFingerprint"`
	ReceiptActorPrincipalID string                 `json:"receiptActorPrincipalId"`
	RequestFingerprint      string                 `json:"requestFingerprint"`
	Outcome                 string                 `json:"outcome"`
	Receipt                 map[string]interface{} `json:"receipt"`
	PairDigest              *string                `json:"pairDigest"`
	CurrentState            *coownerCurrentState   `json:"currentState"`
	Completion              *coownerCompletion     `json:"completion"`
}

type coownerObservation struct {
	receipt  stagedReceipt
	record   enrollmentRecordValue
	command  stagedCommand
	snapshot stateSnapshot
	pair     stagedPair
	current  coownerCurrentState
}

func newCoownerInspection(entry *domainEntry) coownerInspection {
	i := entry.enrollment.input
	return coownerInspection{ContractRevision: EnrollmentCoownerRevision, Mode: "inspect", RequestID: i.RequestID, Scope: i.Request.Scope, InspectionFingerprint: entry.lease.IntentFingerprint, ReceiptActorPrincipalID: *i.ReceiptActorPrincipalID, RequestFingerprint: coownerRequestFingerprint(i.Request), Outcome: "unknown"}
}

func (s *Server) inspectCoowner(ctx context.Context, d *domainEngine, entry *domainEntry) (DomainBegin, error) {
	owned, present := d.lookupDomainScope(entry.lease.Scope)
	if !present {
		return d.completeEnrollment(entry, nil, fmt.Errorf("inspection scope unavailable"))
	}
	d.bindEnrollmentEntry(entry, enrollmentDescriptor(owned.Binding, d.config.ProvisioningProfile), "")
	result, pair, err := s.observeCoowner(ctx, d, entry)
	if err != nil {
		return d.completeEnrollment(entry, nil, err)
	}
	body, err := CanonicalDomainJSON(result)
	d.mu.Lock()
	entry.enrollment.inspection, entry.pair = &result, pair
	d.mu.Unlock()
	return d.completeEnrollment(entry, body, err)
}

func (s *Server) observeCoowner(ctx context.Context, d *domainEngine, entry *domainEntry) (coownerInspection, *DomainPairConfirmation, error) {
	result := newCoownerInspection(entry)
	permit, err := s.sourceFence().beginRead(nil)
	if err != nil {
		return result, nil, nil
	}
	defer permit.release()
	s.forestMutex.RLock()
	if err = s.authorizeCoownerInspectorLocked(d, entry); err != nil {
		s.forestMutex.RUnlock()
		return result, nil, err
	}
	observation, err := s.coownerObservationLocked(d, entry, result.ReceiptActorPrincipalID)
	s.forestMutex.RUnlock()
	if err != nil {
		return result, nil, nil
	}
	witness, err := s.inspectEnrollmentPair(ctx, observation.snapshot, observation.pair, entry.owned.Bounds.MaxSnapshotBytes)
	if err != nil {
		return result, nil, nil
	}
	defer witness.close()
	if permit.recheck() != nil || !witness.current() {
		return result, nil, nil
	}
	pair := domainPair(entry, observation.command, witness.stamp)
	digest := coownerHash(pair)
	result.Outcome, result.PairDigest, result.CurrentState = "committed", &digest, &observation.current
	result.Receipt = coownerReceiptFields(observation.record.Request, observation.receipt.AfterRevision, observation.record.RequestFingerprint, observation.record.ACLEffectDigest, entry.lease.Binding)
	result.Completion = &coownerCompletion{Effect: "settled", OriginalExchange: coownerOriginalCompletion(d, observation.command)}
	if result.CurrentState.State == "unresolved" {
		result.Completion.Effect = "retained"
	}
	return result, pair, nil
}

func (s *Server) authorizeCoownerInspectorLocked(d *domainEngine, entry *domainEntry) error {
	actor := entry.enrollment.actor
	if err := d.enrollmentLive(entry); err != nil {
		return err
	}
	if actor.CoownerAuthority == nil || !actor.CoownerAuthority.ReceiptAuthorized || actor.ReceiptActorPrincipalID == nil {
		return fmt.Errorf("current retained-command receipt authorization required")
	}
	if actor.PrincipalID == *actor.ReceiptActorPrincipalID {
		return nil
	}
	return s.authorizeEnrollmentRootLocked(d, entry)
}

func (s *Server) coownerObservationLocked(d *domainEngine, entry *domainEntry, original string) (coownerObservation, error) {
	var result coownerObservation
	scope := s.stagedScopes[entry.owned.Binding.ScopeID]
	if scope == nil || !scope.reconciled || scope.pending != nil {
		return result, fmt.Errorf("co-owner effect not settled")
	}
	actor := EnrollmentVerified{PrincipalID: original, Request: entry.enrollment.input.Request, RequestFingerprint: coownerRequestFingerprint(entry.enrollment.input.Request)}
	result.command = enrollmentCommand(actor, scope.descriptor.Binding)
	key := stagedCommandKey(result.command)
	receipt, err := s.enrollmentHistoryLocked(scope, key)
	if err != nil || receipt.Command != result.command {
		return result, fmt.Errorf("exact historical co-owner command absent")
	}
	if err = validateEnrollmentReceipt(scope.descriptor.Binding, receipt, scope.descriptor.Bounds.MaxScopeBytes); err != nil {
		return result, err
	}
	result.receipt = receipt
	result.record, err = decodeEnrollmentRecord(receipt.EnrollmentRecord, scope.descriptor.Bounds.MaxScopeBytes)
	if err != nil {
		return result, err
	}
	result.snapshot, err = s.coownerReadSnapshotLocked()
	if err != nil {
		return result, err
	}
	var present bool
	result.pair, present = result.snapshot.pairs[stagedPairKey(scope.descriptor.Binding.ScopeID, key)]
	if !present {
		return result, fmt.Errorf("actual historical pair missing")
	}
	result.current, err = s.coownerCurrentStateLocked(d, entry)
	return result, err
}

// Capture actual current bytes without creating another candidate or incrementing a sequence.
func (s *Server) coownerReadSnapshotLocked() (stateSnapshot, error) {
	data, err := encodeState(s.forest)
	if err != nil {
		return stateSnapshot{}, err
	}
	pairs, err := stagedPairsFromBytes(data)
	if err != nil {
		return stateSnapshot{}, err
	}
	hash := sha256.Sum256(data)
	writer := s.stateWriter
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	if writer.durableSeq == 0 || writer.durablePath != s.statePath() || !compareHashes(writer.durableHash, hash[:]) || !equalStagedPairs(writer.durablePairs, pairs) {
		return stateSnapshot{}, fmt.Errorf("current published snapshot sequence unavailable")
	}
	// The cache only identifies a sequence; inspectEnrollmentPair must still read/fsync the actual file.
	return stateSnapshot{seq: writer.durableSeq, data: data, hash: hash[:], path: s.statePath(), pairs: pairs}, nil
}

func (s *Server) coownerCurrentStateLocked(d *domainEngine, entry *domainEntry) (coownerCurrentState, error) {
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return coownerCurrentState{}, err
	}
	root := index[entry.owned.Binding.RootID]
	if root == nil {
		return coownerCurrentState{}, fmt.Errorf("co-owner root missing")
	}
	revision, err := stagedContentRevision(root)
	if err != nil {
		return coownerCurrentState{}, err
	}
	policy := &domainOwnerPolicy{key: d.config.ACLMetadataKey}
	acl, err := policy.acl(DomainRecord{ID: root.ID, Kind: root.Kind, Metadata: root.Metadata})
	if err != nil {
		return coownerCurrentState{}, err
	}
	result := coownerCurrentState{ScopeRevision: revision, State: "unresolved"}
	c, present := acl.Coowners[*entry.enrollment.input.Request.TargetPrincipalID]
	if !present {
		return result, nil
	}
	result.State = c.State
	if c.GrantRevision != coownerOwnerRevision(entry.enrollment.input.Request) {
		result.State = "superseded"
	}
	result.OwnerGrantRevision, result.GrantCommandID, result.GrantFingerprint = &c.GrantRevision, &c.GrantCommandID, &c.GrantFingerprint
	if s.coownerCurrentPinsLocked(d, entry, c) != nil {
		result.State, result.OwnerGrantRevision, result.GrantCommandID, result.GrantFingerprint = "unresolved", nil, nil, nil
	}
	return result, nil
}

func (s *Server) coownerCurrentPinsLocked(d *domainEngine, entry *domainEntry, current domainCoownerContribution) error {
	root, records, err := s.enrollmentPinRecordsLocked(entry)
	if err != nil {
		return err
	}
	reader := newDomainACLReader(d.config.ACLMetadataKey, entry.owned, root)
	for _, record := range records {
		kind := enrollmentSemanticKind(entry.owned.Layout, record.Kind)
		if kind == "" {
			continue
		}
		acl, err := reader.acl(record)
		if err != nil {
			return err
		}
		if err = coownerCurrentACL(acl, entry.enrollment.input.Request, kind, current, d.config.ProvisioningProfile); err != nil {
			return err
		}
	}
	return nil
}

func coownerCurrentACL(acl domainACL, r EnrollmentRequest, kind string, current domainCoownerContribution, profile *DomainProvisioningProfile) error {
	if current.ProfileRef != profile.ProfileRef {
		return fmt.Errorf("current co-owner profile changed")
	}
	if err := coownerPriorIdentity(acl, r, kind, current); err != nil {
		return err
	}
	if current.State == "installed" {
		grants := coownerBoundedGrants(profile.OwnerGrants[kind], acl.Principals[r.CoownerChange.FounderPrincipalID], current.GrantRevision)
		if kind == "root" {
			coownerControlGrants(grants, current.GrantRevision)
		}
		if !domainEqual(grants, acl.Coowners[*r.TargetPrincipalID].Grants) {
			return fmt.Errorf("current co-owner bounded grants changed")
		}
	}
	for name, template := range acl.CreateACLs {
		if profile.Layout.Kinds[name] == "" {
			continue
		}
		if err := coownerCurrentACL(template, r, name, current, profile); err != nil {
			return err
		}
	}
	return nil
}

func coownerOriginalCompletion(d *domainEngine, command stagedCommand) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, entry := range d.entries {
		// A rejected admission/replay never issued an exchange to finish.
		if entry.enrollment == nil || entry.enrollment.input.Mode != "apply" || !entry.finished || entry.pendingKey != "" || entry.responseHash == "" {
			continue
		}
		if enrollmentCommand(entry.enrollment.actor, entry.owned.Binding) == command {
			return "finished"
		}
	}
	return "unproven"
}
