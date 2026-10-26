// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

type DomainInputProjector interface {
	ProjectInput(string, DomainInput, DomainIntent, DomainOwnedScope, DomainView) ([]byte, error)
}

func (s *Server) domainStoreResult(entry *domainEntry) (interface{}, error) {
	if entry.intent.ContractRevision != "png-native-store/0.1" {
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
	var result interface{}
	if err = DecodeDomainJSON(receipt.ProductIntent, &result); err != nil {
		return nil, err
	}
	return result, nil
}
