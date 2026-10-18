// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"fmt"
)

func (s *Server) DomainCall(ctx context.Context, request DomainRequest) (DomainBegin, error) {
	d, err := s.domainEngine()
	if err != nil {
		return DomainBegin{}, err
	}
	if request.RequestID == "" || len(request.RequestID) > d.config.MaxRequestBytes {
		return DomainBegin{}, fmt.Errorf("bounded request correlation required")
	}
	s.forestMutex.RLock()
	intent, owned, _, err := s.resolveDomainLocked(d, request.DomainInput)
	s.forestMutex.RUnlock()
	if err != nil {
		return DomainBegin{}, err
	}
	actor, err := d.verify(ctx, request.Proof, "admission", intent, nil)
	if err != nil {
		return DomainBegin{}, err
	}
	entry, err := d.reserve(actor, request.DomainInput, owned)
	if err != nil {
		return DomainBegin{}, err
	}
	var body []byte
	if request.Mode == "read" {
		body, err = s.projectDomainRead(d, entry, request.RequestID)
	} else {
		body, err = s.executeDomainCommand(d, entry, request.RequestID)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	entry.executing = false
	if err != nil || len(body) > d.config.MaxResponseBytes {
		entry.body = nil
		entry.disposition = "irrevocably-discarded"
		entry.finished = entry.pendingKey == ""
		return DomainBegin{}, fmt.Errorf("native result denied/unavailable")
	}
	entry.body = body
	entry.responseHash = stagedHash(body)
	return DomainBegin{Lease: entry.lease, ExchangeID: entry.lease.LeaseID, ResponseHash: entry.responseHash}, nil
}
func (s *Server) projectDomainRead(d *domainEngine, entry *domainEntry, requestID string) ([]byte, error) {
	s.forestMutex.RLock()
	defer s.forestMutex.RUnlock()
	current, _, view, err := s.resolveDomainLocked(d, entry.input)
	if err != nil {
		return nil, err
	}
	if !domainEqual(current, entry.intent) {
		return nil, fmt.Errorf("native read intent changed")
	}
	if err = d.authorizeIntentLocked(entry.actor, view); err != nil {
		return nil, err
	}
	view, err = cloneDomainResolveView(view, entry.owned.Bounds)
	if err != nil {
		return nil, err
	}
	return entry.product.Project(requestID, entry.intent, entry.owned, view)
}
func (s *Server) executeDomainCommand(d *domainEngine, entry *domainEntry, requestID string) ([]byte, error) {
	command, err := entry.product.Command(entry.input)
	if err != nil {
		return nil, err
	}
	if err = validateDomainReceiptBound(d, entry, requestID, command); err != nil {
		return nil, err
	}
	native := stagedCommand{PrincipalID: entry.actor.PrincipalID, AccountID: entry.actor.Scope.AccountID, ScopeID: entry.owned.Binding.ScopeID, CommandID: command.CommandID, ExpectedRevision: command.ExpectedRevision, Action: command.Operation, BodySHA256: entry.intent.RequestFingerprint}
	build := s.domainBuilder(d, entry, command.Operation)
	result, err := s.stageOwnedCommand(native, s.domainAuthorizer(d, entry), build)
	if result.Durable != nil {
		d.mu.Lock()
		entry.pair = domainPair(entry, native, *result.Durable)
		entry.receiptKey = entry.pair.ReceiptKey
		d.mu.Unlock()
	}
	pending := s.captureDomainPending(d, entry, native, result)
	if err != nil && result.Status != "conflict" && !pending {
		return nil, err
	}
	revision := interface{}(nil)
	if result.Durable != nil {
		revision = result.Revision
	}
	receipt := map[string]interface{}{"commandId": command.CommandID, "expectedRevision": command.ExpectedRevision, "operation": command.Operation, "requestFingerprint": entry.intent.RequestFingerprint, "status": result.Status, "revision": revision}
	return CanonicalDomainJSON(map[string]interface{}{"contractRevision": entry.intent.ContractRevision, "requestId": requestID, "scope": entry.intent.Scope, "receipt": receipt})
}

func validateDomainReceiptBound(d *domainEngine, entry *domainEntry, requestID string, command DomainCommand) error {
	revision := "lj.owned/v1:" + stagedHash(nil)
	receipt := map[string]interface{}{"commandId": command.CommandID, "expectedRevision": command.ExpectedRevision, "operation": command.Operation, "requestFingerprint": entry.intent.RequestFingerprint, "status": "replayed", "revision": revision}
	body, err := CanonicalDomainJSON(map[string]interface{}{"contractRevision": entry.intent.ContractRevision, "requestId": requestID, "scope": entry.intent.Scope, "receipt": receipt})
	if err != nil {
		return err
	}
	if len(body) > d.config.MaxResponseBytes {
		return fmt.Errorf("explicit response bound cannot hold a paired receipt")
	}
	return nil
}

func (s *Server) DomainCompletedLeases() []DomainCompletion {
	d, err := s.domainEngine()
	if err != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	result := []DomainCompletion{}
	for id, entry := range d.entries {
		if entry.finished {
			result = append(result, DomainCompletion{LeaseID: id, ResponseHash: entry.responseHash, Disposition: entry.disposition, PermitID: entry.permitID})
		}
	}
	return result
}
func (s *Server) domainBuilder(d *domainEngine, entry *domainEntry, operation string) stagedBuilder {
	return func(native stagedView) (stagedDelta, error) {
		view := domainView(native, d.config.ACLMetadataKey)
		view.CreateACL = func(kind string) (interface{}, error) {
			return d.policy.CreateACLLocked(entry.actor, operation, kind, view.Records[entry.owned.Binding.RootID])
		}
		return entry.product.Build(entry.input, entry.owned, view)
	}
}
func (s *Server) captureDomainPending(d *domainEngine, entry *domainEntry, command stagedCommand, result stagedResult) bool {
	s.forestMutex.RLock()
	scope := s.stagedScopes[command.ScopeID]
	if result.Status != "unknown" || scope.pending == nil || scope.pending.receipt.Fingerprint != stagedCommandFingerprint(entry.owned.Binding, command) {
		s.forestMutex.RUnlock()
		return false
	}
	key := scope.pending.key
	s.forestMutex.RUnlock()
	d.mu.Lock()
	entry.pendingKey = key
	entry.receiptKey = key
	d.mu.Unlock()
	return true
}
func domainPair(entry *domainEntry, command stagedCommand, stamp stagedDurableStamp) *DomainPairConfirmation {
	return &DomainPairConfirmation{Epoch: entry.lease.Epoch, ScopeID: command.ScopeID, ReceiptKey: stamp.Pair.Key, NativeFingerprint: stamp.Pair.Fingerprint, RequestFingerprint: command.BodySHA256, ExpectedRevision: command.ExpectedRevision, Revision: stamp.Pair.AfterRevision, ReceiptHash: stamp.Pair.ReceiptHash, Sequence: stamp.Sequence, SnapshotHash: stamp.SnapshotHash, CommandID: command.CommandID, PrincipalID: command.PrincipalID, Scope: entry.lease.Scope, Binding: entry.lease.Binding}
}
func (s *Server) DomainEpoch() (string, error) {
	d, err := s.domainEngine()
	if err != nil {
		return "", err
	}
	return d.epoch, nil
}
func (s *Server) DomainLeaseLimit() (int, error) {
	d, err := s.domainEngine()
	if err != nil {
		return 0, err
	}
	return d.config.MaxLeases, nil
}
