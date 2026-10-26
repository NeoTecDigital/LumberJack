// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

func validateNativeStoreReceipt(binding stagedBinding, receipt stagedReceipt, result nativeStoreProductResult, maximum int) error {
	if receipt.Command.Action != nativeStoreCommand || receipt.Command.AccountID != binding.AccountID || receipt.Command.ScopeID != binding.ScopeID {
		return fmt.Errorf("native result action/account/scope mismatch")
	}
	targets := map[string]bool{}
	for _, target := range receipt.Targets {
		targets[target.NodeID] = true
	}
	aliases, canonical := map[string]bool{}, map[string]bool{}
	for _, record := range result.Records {
		if err := validateNativeReceiptRecord(record, binding.AccountID, maximum); err != nil {
			return err
		}
		identity := record.Family + "\x00" + record.Key
		if aliases[record.NativeID] || canonical[identity] || !targets[record.NativeID] {
			return fmt.Errorf("native result alias/target ambiguity")
		}
		aliases[record.NativeID], canonical[identity] = true, true
	}
	return nil
}
func validateNativeReceiptRecord(record nativeStoreReceiptRecord, account string, maximum int) error {
	if validateStagedIdentifiers(stagedBounds{MaxIdentifierBytes: maximum}, record.Family, record.Key, record.NativeID) != nil || !domainValidHash(record.Version) {
		return fmt.Errorf("bounded retained native record identity/version required")
	}
	if record.Data == nil || record.Data["account_id"] != account || record.Data["id"] != record.Key {
		return fmt.Errorf("retained native canonical identity/account mismatch")
	}
	return nil
}
