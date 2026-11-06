// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

type DomainInputProjector interface {
	ProjectInput(string, DomainInput, DomainIntent, DomainOwnedScope, DomainView) ([]byte, error)
}

// A compiled product may project its own already-paired receipt targets only.
type DomainCommandResultProjector interface {
	ProjectCommand(DomainInput, DomainOwnedScope, DomainRetainedReceipt) (interface{}, error)
}

func (s *Server) domainStoreResult(entry *domainEntry) (interface{}, error) {
	projector, projected := entry.product.(DomainCommandResultProjector)
	if entry.intent.ContractRevision != "png-native-store/0.1" && !projected {
		return nil, nil
	}
	if entry.receiptKey == "" {
		return nil, fmt.Errorf("native store receipt unconfirmed")
	}
	s.forestMutex.RLock()
	defer s.forestMutex.RUnlock()
	scope := s.stagedScopes[entry.owned.Binding.ScopeID]
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return nil, err
	}
	raw, present := index[entry.owned.Binding.RootID].CommandReceipts[entry.receiptKey]
	if scope.pending != nil && scope.pending.key == entry.receiptKey {
		raw, present = scope.pending.receipt, true
	}
	if !present {
		return nil, fmt.Errorf("retained native result absent")
	}
	var receipt stagedReceipt
	if err = decodeStagedInternal(raw, &receipt); err != nil {
		return nil, err
	}
	if projected {
		return projector.ProjectCommand(entry.input, entry.owned, DomainRetainedReceipt{Key: entry.receiptKey, Receipt: receipt})
	}
	var result interface{}
	if err = DecodeDomainJSON(receipt.ProductIntent, &result); err != nil {
		return nil, err
	}
	return result, nil
}
