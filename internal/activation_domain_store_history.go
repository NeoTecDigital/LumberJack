// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

type DomainRetainedReceipt struct {
	Key     string
	Receipt stagedReceipt
}

func domainRetainedReceipts(rootReceipts map[string]interface{}) (map[string]DomainRetainedReceipt, error) {
	result := map[string]DomainRetainedReceipt{}
	for key, raw := range rootReceipts {
		if key == stagedScopeKey {
			continue
		}
		var receipt stagedReceipt
		if err := decodeStagedInternal(raw, &receipt); err != nil {
			return nil, err
		}
		if receipt.Command.Action != "png.store.write.define" {
			continue
		}
		if _, exists := result[receipt.Command.CommandID]; exists {
			return nil, fmt.Errorf("retained command identity ambiguous")
		}
		result[receipt.Command.CommandID] = DomainRetainedReceipt{Key: key, Receipt: receipt}
	}
	return result, nil
}
