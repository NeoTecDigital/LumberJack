// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
	"sort"
)

const nativeStoreCommand = "png.store.write.define"
const nativeProductV2 = "manifest-associates/0.2"

type nativeStoreReceiptRecord struct {
	Family   string                 `json:"family"`
	Key      string                 `json:"key"`
	NativeID string                 `json:"native_id"`
	Version  string                 `json:"version"`
	Data     map[string]interface{} `json:"data"`
}
type nativeStoreProductResult struct {
	Records []nativeStoreReceiptRecord `json:"records"`
	Result  json.RawMessage            `json:"result"`
}
type nativeStoreResultValues struct {
	CommandDigest          *string `json:"command_digest,omitempty"`
	DeriveCarrierEvents    *bool   `json:"derive_carrier_events,omitempty"`
	DerivedAssetEventCount *int    `json:"derived_asset_event_count,omitempty"`
	ApprovalRef            *string `json:"approval_ref,omitempty"`
}

func decodeProductIntent(raw []byte, maximum int) (interface{}, error) {
	if maximum <= 0 || len(raw) == 0 || len(raw) > maximum {
		return nil, fmt.Errorf("bounded product receipt payload required")
	}
	var shape map[string]json.RawMessage
	if err := DecodeDomainJSON(raw, &shape); err != nil {
		return nil, err
	}
	if _, present := shape["records"]; present {
		return decodeNativeStoreResult(raw, shape, maximum)
	}
	if err := productIntentKeys(shape); err != nil {
		return nil, err
	}
	var intent DomainIntent
	if err := DecodeDomainJSON(raw, &intent); err != nil {
		return nil, err
	}
	if intent.ContractRevision != nativeProductV2 || intent.Mode != "command" || intent.Operation == nil || *intent.Operation == "" {
		return nil, fmt.Errorf("explicit current product /.2 declaration required")
	}
	return intent, nil
}
func decodeNativeStoreResult(raw []byte, shape map[string]json.RawMessage, maximum int) (interface{}, error) {
	if len(shape) != 2 || shape["result"] == nil {
		return nil, fmt.Errorf("closed native retained result required")
	}
	var result nativeStoreProductResult
	if err := DecodeDomainJSON(raw, &result); err != nil {
		return nil, err
	}
	if len(result.Records) == 0 || len(result.Records) > maximum {
		return nil, fmt.Errorf("nonempty bounded native result records required")
	}
	if err := validateNativeResultValues(result.Result, maximum); err != nil {
		return nil, err
	}
	return result, nil
}
func validateNativeResultValues(raw []byte, maximum int) error {
	if string(raw) == "null" {
		return nil
	}
	var shape map[string]json.RawMessage
	if err := DecodeDomainJSON(raw, &shape); err != nil {
		return err
	}
	for _, value := range shape {
		if string(value) == "null" {
			return fmt.Errorf("native result field cannot be explicit null")
		}
	}
	var result nativeStoreResultValues
	if err := DecodeDomainJSON(raw, &result); err != nil {
		return err
	}
	if result.CommandDigest != nil && !domainValidHash(*result.CommandDigest) {
		return fmt.Errorf("retained command digest invalid")
	}
	if result.DerivedAssetEventCount != nil && *result.DerivedAssetEventCount < 0 {
		return fmt.Errorf("retained derivation count invalid")
	}
	if result.ApprovalRef != nil {
		return validateStagedIdentifiers(stagedBounds{MaxIdentifierBytes: maximum}, *result.ApprovalRef)
	}
	return nil
}
func productIntentKeys(shape map[string]json.RawMessage) error {
	required := []string{"contractRevision", "scope", "binding", "mode", "operation", "method", "target", "requestFingerprint", "resources", "fields"}
	for _, key := range required {
		if shape[key] == nil || string(shape[key]) == "null" {
			return fmt.Errorf("required product intent field missing")
		}
	}
	if len(shape) < len(required) || len(shape) > len(required)+2 {
		return fmt.Errorf("closed product intent required")
	}
	return nil
}
func validateProductReceiptIntent(binding stagedBinding, receipt stagedReceipt, maximum int) error {
	if len(receipt.ProductIntent) == 0 {
		if receipt.Command.Action == nativeStoreCommand {
			return fmt.Errorf("native result declaration required")
		}
		return nil // Legacy commands do not silently become /.2 commands.
	}
	if len(receipt.EnrollmentRecord) != 0 || len(receipt.MappingRecord) != 0 {
		return fmt.Errorf("mixed receipt grammars denied")
	}
	value, err := decodeProductIntent(receipt.ProductIntent, maximum)
	if err != nil {
		return err
	}
	if result, native := value.(nativeStoreProductResult); native {
		return validateNativeStoreReceipt(binding, receipt, result, maximum)
	}
	if receipt.Command.Action == nativeStoreCommand {
		return fmt.Errorf("native result is not DomainIntent")
	}
	intent := value.(DomainIntent)
	scope := DomainScope{AccountID: binding.AccountID, Product: binding.ProductID}
	expected := DomainBinding{Scope: scope, RootID: binding.RootID, BindingRevision: binding.BindingRevision}
	if intent.Scope != scope || intent.Binding != expected || receipt.Command.AccountID != binding.AccountID || receipt.Command.ScopeID != binding.ScopeID || *intent.Operation != receipt.Command.Action || intent.RequestFingerprint != receipt.Command.BodySHA256 {
		return fmt.Errorf("product intent command/native binding mismatch")
	}
	return validateProductIntentFields(intent, maximum)
}
func validateProductIntentFields(intent DomainIntent, maximum int) error {
	if intent.Method == "" || intent.Target == "" || !domainValidHash(intent.RequestFingerprint) || len(intent.Resources) == 0 || len(intent.Resources) != len(intent.Fields) {
		return fmt.Errorf("complete typed product intent required")
	}
	seen := map[string]bool{}
	for index, resource := range intent.Resources {
		if resource.AccountID != intent.Scope.AccountID || validateStagedIdentifiers(stagedBounds{MaxIdentifierBytes: maximum}, resource.Kind, resource.ResourceID) != nil || seen[resource.ResourceID] {
			return fmt.Errorf("unique account-scoped native resources required")
		}
		seen[resource.ResourceID] = true
		fields := intent.Fields[index]
		if !domainEqual(fields.Resource, resource) || len(fields.Fields) == 0 || !sort.StringsAreSorted(fields.Fields) {
			return fmt.Errorf("canonical resource field group required")
		}
		if err := validateProductFieldNames(fields.Fields, maximum); err != nil {
			return err
		}
	}
	return nil
}
func validateProductFieldNames(fields []string, maximum int) error {
	previous := ""
	for _, field := range fields {
		if field == previous || validateStagedIdentifiers(stagedBounds{MaxIdentifierBytes: maximum}, field) != nil {
			return fmt.Errorf("nonempty unique fields required")
		}
		previous = field
	}
	return nil
}
