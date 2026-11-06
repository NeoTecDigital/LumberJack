// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

func stagedPairKey(scopeID, key string) string {
	data, _ := json.Marshal([]string{scopeID, key})
	return string(data)
}

func stagedCommandKey(command stagedCommand) string {
	data, _ := json.Marshal([]string{command.PrincipalID, command.AccountID, command.ScopeID, command.CommandID})
	return stagedReceiptPrefix + stagedHash(data)
}

func isStagedReceiptKey(key string) bool {
	return strings.HasPrefix(key, stagedReceiptPrefix)
}

func stagedCommandFingerprint(binding stagedBinding, command stagedCommand) string {
	data, _ := json.Marshal([]interface{}{binding, command})
	return stagedHash(data)
}

func validateStagedCommand(scope *stagedScope, command stagedCommand) error {
	binding := scope.descriptor.Binding
	if command.AccountID != binding.AccountID || command.ScopeID != binding.ScopeID {
		return fmt.Errorf("command account/scope mismatch")
	}
	if err := validateStagedIdentifiers(scope.descriptor.Bounds, command.PrincipalID, command.AccountID, command.ScopeID, command.CommandID, command.Action); err != nil {
		return err
	}
	bodyHash, err := hex.DecodeString(command.BodySHA256)
	if err != nil || len(bodyHash) != 32 || command.ExpectedRevision == "" {
		return fmt.Errorf("command has no exact body digest or expected revision")
	}
	return nil
}

func stagedReceiptPair(binding stagedBinding, key string, data []byte) (stagedPair, error) {
	var receipt stagedReceipt
	if !isStagedReceiptKey(key) || decodeStagedProductReceipt(data, &receipt, len(data)) != nil {
		return stagedPair{}, fmt.Errorf("invalid typed owned receipt")
	}
	if receipt.Version != 1 || receipt.Command.AccountID != binding.AccountID || receipt.Command.ScopeID != binding.ScopeID ||
		key != stagedCommandKey(receipt.Command) || receipt.Fingerprint != stagedCommandFingerprint(binding, receipt.Command) || receipt.AfterRevision == "" {
		return stagedPair{}, fmt.Errorf("owned receipt identity/fingerprint mismatch")
	}
	if err := validateProductReceiptIntent(binding, receipt, len(data)); err != nil {
		return stagedPair{}, err
	}
	if err := validateEnrollmentReceipt(binding, receipt, len(data)); err != nil {
		return stagedPair{}, err
	}
	if err := validateCanonicalReceipt(binding, receipt, len(data)); err != nil {
		return stagedPair{}, err
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return stagedPair{}, err
	}
	return stagedPair{ScopeID: binding.ScopeID, Key: key, Fingerprint: receipt.Fingerprint,
		AfterRevision: receipt.AfterRevision, ReceiptHash: stagedHash(canonical)}, nil
}

func cloneStagedReceiptMap(source map[string]interface{}) (map[string]interface{}, error) {
	if source == nil {
		return nil, nil
	}
	cloned := map[string]interface{}{}
	for key, value := range source {
		copy, err := cloneStagedInternalReceipt(key, value)
		if err != nil {
			return nil, err
		}
		cloned[key] = copy
	}
	return cloned, nil
}

func cloneStagedInternalReceipt(key string, value interface{}) (interface{}, error) {
	if key == stagedScopeKey {
		var descriptor stagedDescriptor
		err := decodeStagedInternal(value, &descriptor)
		return descriptor, err
	}
	var receipt stagedReceipt
	if !isStagedReceiptKey(key) || decodeStagedInternal(value, &receipt) != nil {
		return nil, fmt.Errorf("owned receipt map contains unsupported state")
	}
	return receipt, nil
}

func authorizeStagedTarget(authorize stagedAuthorizer, binding stagedBinding, command stagedCommand, target stagedTarget) error {
	return authorize(stagedAccess{Binding: binding, PrincipalID: command.PrincipalID,
		Action: command.Action, NodeID: target.NodeID, Kind: target.Kind, Fields: append([]string(nil), target.Fields...)})
}

func authorizeStagedReplay(authorize stagedAuthorizer, binding stagedBinding, receipt stagedReceipt) error {
	for _, target := range receipt.Targets {
		if err := authorizeStagedTarget(authorize, binding, receipt.Command, target); err != nil {
			return err
		}
	}
	return nil
}

func matchingStagedPair(pairs map[string]stagedPair, requirement stagedPair) bool {
	actual, present := pairs[stagedPairKey(requirement.ScopeID, requirement.Key)]
	return present && actual == requirement
}

func equalStagedPairs(left, right map[string]stagedPair) bool {
	if len(left) != len(right) {
		return false
	}
	for key, pair := range left {
		if right[key] != pair {
			return false
		}
	}
	return true
}

// The closed legacy outer grammar is unchanged. Only canonical trusted /.2 intent
// is nullable; configured scope/request limits are checked before admission/replay.
func decodeStagedProductReceipt(data []byte, target *stagedReceipt, maximum int) error {
	if len(data) == 0 || len(data) > maximum {
		return fmt.Errorf("bounded typed receipt required")
	}
	var shape map[string]json.RawMessage
	if err := DecodeDomainJSON(data, &shape); err != nil {
		return err
	}
	product, productPresent := shape["productIntent"]
	enrollment, enrollmentPresent := shape["enrollmentRecord"]
	mapping, mappingPresent := shape["mappingRecord"]
	count := 0
	for _, present := range []bool{productPresent, enrollmentPresent, mappingPresent} {
		if present {
			count++
		}
	}
	if count > 1 {
		return fmt.Errorf("mixed receipt vocabularies denied")
	}
	if !productPresent && !enrollmentPresent && !mappingPresent {
		return strictActivationJSON(data, target)
	}
	delete(shape, "productIntent")
	delete(shape, "enrollmentRecord")
	delete(shape, "mappingRecord")
	outer, err := json.Marshal(shape)
	if err != nil {
		return err
	}
	if err = strictActivationJSON(outer, target); err != nil {
		return err
	}
	return decodeStagedReceiptMember(target, product, enrollment, mapping, productPresent, mappingPresent, maximum)
}
func decodeStagedReceiptMember(target *stagedReceipt, product, enrollment, mapping json.RawMessage, productPresent, mappingPresent bool, maximum int) error {
	var err error
	if mappingPresent {
		var record canonicalMutationRecord
		if sourceDecode(mapping, &record, PersonalSourceBounds{MaxRequestBytes: maximum}) != nil {
			return sourceInvalid()
		}
		target.MappingRecord, err = CanonicalDomainJSON(record)
	} else if productPresent {
		intent, decodeErr := decodeProductIntent(product, maximum)
		if decodeErr != nil {
			return decodeErr
		}
		target.ProductIntent, err = CanonicalDomainJSON(intent)
	} else {
		record, decodeErr := decodeEnrollmentRecord(enrollment, maximum)
		if decodeErr != nil {
			return decodeErr
		}
		target.EnrollmentRecord, err = CanonicalDomainJSON(record)
	}
	return err
}
