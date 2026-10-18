// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

// domainEvaluation belongs to ONE uninterrupted forest lock hold. It is never
// attached to a Server, lease, request or entry and retains no temporal callbacks.
// Its records are private: Resolve and policy callbacks receive separate copies.
type domainEvaluation struct {
	intent  DomainIntent
	binding DomainNativeBinding
	records map[string]DomainRecord
}

func newDomainEvaluation(intent DomainIntent, view DomainView) (*domainEvaluation, error) {
	raw, err := CanonicalDomainJSON(intent)
	if err != nil {
		return nil, err
	}
	var private DomainIntent
	if err = DecodeDomainJSON(raw, &private); err != nil {
		return nil, err
	}
	return &domainEvaluation{intent: private, binding: view.Binding, records: view.Records}, nil
}

// The two callers own the lifetime: prepareOwnedCommand holds one exclusive
// forest lock; authorizeDomainHandoffLocked holds one uninterrupted read lock.
// Reuse across either lock boundary is forbidden; a new authorizer is required.
func (s *Server) domainEvaluationAuthorizer(d *domainEngine, entry *domainEntry, evaluation *domainEvaluation) stagedAuthorizer {
	return func(access stagedAccess) error {
		if err := s.domainEvaluationCurrentLocked(d, entry, access); err != nil {
			return err
		}
		var err error
		evaluation, err = s.loadDomainEvaluationLocked(d, entry, evaluation)
		if err != nil {
			return err
		}
		return evaluation.authorize(d, entry, access)
	}
}

func (s *Server) loadDomainEvaluationLocked(d *domainEngine, entry *domainEntry, current *domainEvaluation) (*domainEvaluation, error) {
	if current != nil {
		return current, nil
	}
	intent, _, view, err := s.resolveDomainLocked(d, entry.input)
	if err != nil {
		return nil, err
	}
	return newDomainEvaluation(intent, view)
}

func (s *Server) domainHandoffReceiptLocked(entry *domainEntry) (stagedReceipt, error) {
	scope := s.stagedScopes[entry.owned.Binding.ScopeID]
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return stagedReceipt{}, err
	}
	raw, present := index[entry.owned.Binding.RootID].CommandReceipts[entry.receiptKey]
	if scope.pending != nil && scope.pending.key == entry.receiptKey {
		raw, present = scope.pending.receipt, true
	}
	if !present {
		return stagedReceipt{}, fmt.Errorf("paired command history unavailable")
	}
	var receipt stagedReceipt
	err = decodeStagedInternal(raw, &receipt)
	return receipt, err
}

func (s *Server) domainEvaluationCurrentLocked(d *domainEngine, entry *domainEntry, access stagedAccess) error {
	if entry.actor.ExpiresAt <= domainNow() || access.Binding != entry.owned.Binding {
		return fmt.Errorf("current domain authority expired/rebound")
	}
	owned, present := d.scopes[entry.intent.Scope]
	scope := s.stagedScopes[entry.owned.Binding.ScopeID]
	if !present || owned.Binding != entry.owned.Binding || scope == nil || !scope.configured || !scope.reconciled || scope.descriptor.Binding != entry.owned.Binding {
		return errStagedUnconfigured
	}
	if entry.input.Mode == "read" && scope.pending != nil {
		return errStagedPending
	}
	return nil
}

func (e *domainEvaluation) authorize(d *domainEngine, entry *domainEntry, access stagedAccess) error {
	if e.binding != entry.owned.Binding || !domainEqual(e.intent, entry.intent) {
		return fmt.Errorf("current intent resources changed")
	}
	view := DomainView{Binding: e.binding, Records: e.records}
	if err := d.authorizeIntentLocked(entry.actor, view); err != nil {
		return err
	}
	if access.NodeID == "" {
		return nil
	}
	return d.authorizeNativeTarget(entry, view, access)
}
