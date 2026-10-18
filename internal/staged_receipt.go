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
	if !isStagedReceiptKey(key) || strictActivationJSON(data, &receipt) != nil {
		return stagedPair{}, fmt.Errorf("invalid typed owned receipt")
	}
	if receipt.Version != 1 || receipt.Command.AccountID != binding.AccountID || receipt.Command.ScopeID != binding.ScopeID ||
		key != stagedCommandKey(receipt.Command) || receipt.Fingerprint != stagedCommandFingerprint(binding, receipt.Command) || receipt.AfterRevision == "" {
		return stagedPair{}, fmt.Errorf("owned receipt identity/fingerprint mismatch")
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
