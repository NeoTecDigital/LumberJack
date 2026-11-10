// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
)

const domainWorkloadRecordRevision = "manifest-native-workload-record/0.1"

type domainWorkloadRecord struct {
	ContractRevision   string            `json:"contractRevision"`
	PrincipalID        string            `json:"principalId"`
	SessionID          string            `json:"sessionId"`
	Workload           DomainWorkloadRun `json:"workload"`
	RequestFingerprint string            `json:"requestFingerprint"`
	IntentFingerprint  string            `json:"intentFingerprint"`
}

func decodeWorkloadRecord(raw []byte, maximum int) (domainWorkloadRecord, error) {
	var record domainWorkloadRecord
	if len(raw) == 0 || len(raw) > maximum {
		return record, fmt.Errorf("bounded workload provenance required")
	}
	keys := []string{"contractRevision", "principalId", "sessionId", "workload", "requestFingerprint", "intentFingerprint"}
	if _, err := enrollmentShape(raw, keys, nil, nil); err != nil {
		return record, err
	}
	if err := DecodeDomainJSON(raw, &record); err != nil {
		return record, err
	}
	if record.ContractRevision != domainWorkloadRecordRevision || validateWorkloadRun(record.Workload) != nil || record.PrincipalID != workloadPrincipal(record.Workload.Grant) || record.SessionID != workloadSession(record.Workload) || !domainValidHash(record.RequestFingerprint) || !domainValidHash(record.IntentFingerprint) {
		return record, fmt.Errorf("exact workload provenance identity required")
	}
	return record, nil
}

func workloadRecordFor(entry *domainEntry) (json.RawMessage, error) {
	if entry.actor.Workload == nil || !domainEqual(entry.actor.Workload, entry.intent.Workload) || entry.input.Mode != "command" || !domainWorkloadIntent(entry.intent) {
		return nil, fmt.Errorf("bound workload command intent required")
	}
	fingerprint, err := DomainIntentHash(entry.intent)
	if err != nil {
		return nil, err
	}
	record := domainWorkloadRecord{domainWorkloadRecordRevision, entry.actor.PrincipalID, entry.actor.SessionID, *entry.actor.Workload, entry.intent.RequestFingerprint, fingerprint}
	raw, err := CanonicalDomainJSON(record)
	if err != nil {
		return nil, err
	}
	_, err = decodeWorkloadRecord(raw, len(raw))
	return raw, err
}

func retainWorkloadRecord(entry *domainEntry, delta *stagedDelta) error {
	if len(delta.WorkloadRecord) != 0 {
		return fmt.Errorf("product cannot supply workload authority/provenance")
	}
	if entry.actor.Workload == nil {
		return nil
	}
	raw, err := workloadRecordFor(entry)
	if err == nil {
		delta.WorkloadRecord = raw
	}
	return err
}

// Runs within the existing forest lock, including zero-target retained commands.
// A product Build is deliberately not involved in this replay decision.
func authorizeWorkloadReplay(entry *domainEntry, access stagedAccess) error {
	if !access.ReplayWorkload {
		return nil
	}
	if entry.actor.Workload == nil {
		if len(access.WorkloadRecord) != 0 {
			return apiErrorf(409, "command_conflict")
		}
		return nil
	}
	expected, err := workloadRecordFor(entry)
	if err != nil {
		return err
	}
	actual, err := decodeWorkloadRecord(access.WorkloadRecord, entry.owned.Bounds.MaxScopeBytes)
	if err != nil {
		return apiErrorf(409, "command_conflict")
	}
	canonical, err := CanonicalDomainJSON(actual)
	if err != nil || string(expected) != string(canonical) {
		return apiErrorf(409, "command_conflict")
	}
	return nil
}

func validateWorkloadReceipt(binding stagedBinding, receipt stagedReceipt, maximum int) error {
	if len(receipt.WorkloadRecord) == 0 {
		return nil
	}
	if receipt.Command.Action != nativeStoreCommand || binding.ProductID != "manifest" || len(receipt.EnrollmentRecord)+len(receipt.MappingRecord)+len(receipt.Followers) != 0 {
		return fmt.Errorf("mixed/unrelated workload provenance denied")
	}
	record, err := decodeWorkloadRecord(receipt.WorkloadRecord, maximum)
	if err != nil {
		return err
	}
	if record.PrincipalID != receipt.Command.PrincipalID || record.Workload.Grant.AccountID != binding.AccountID || receipt.Command.AccountID != binding.AccountID || receipt.Command.BodySHA256 != record.RequestFingerprint {
		return fmt.Errorf("workload receipt command/tuple mismatch")
	}
	return nil
}

func decodeWorkloadReceiptShape(data []byte, target *stagedReceipt, maximum int) (map[string]json.RawMessage, []byte, error) {
	if len(data) == 0 || len(data) > maximum {
		return nil, nil, fmt.Errorf("bounded typed receipt required")
	}
	var shape map[string]json.RawMessage
	if err := DecodeDomainJSON(data, &shape); err != nil {
		return nil, nil, err
	}
	target.WorkloadRecord = nil
	raw, present := shape["workloadRecord"]
	if !present {
		return shape, data, nil
	}
	if _, present := shape["enrollmentRecord"]; present {
		return nil, nil, fmt.Errorf("mixed workload/enrollment receipt denied")
	}
	if _, present := shape["mappingRecord"]; present {
		return nil, nil, fmt.Errorf("mixed workload/mapping receipt denied")
	}
	record, err := decodeWorkloadRecord(raw, maximum)
	if err != nil {
		return nil, nil, err
	}
	target.WorkloadRecord, err = CanonicalDomainJSON(record)
	if err != nil {
		return nil, nil, err
	}
	delete(shape, "workloadRecord")
	outer, err := json.Marshal(shape)
	return shape, outer, err
}

// Only bound workloads use this cross-tuple collision check. Legacy and human
// command-key namespaces remain unchanged; this never rekeys historical receipts.
func (s *Server) authorizeWorkloadCommandKeyLocked(entry *domainEntry, access stagedAccess) error {
	if entry.actor.Workload == nil || access.ReplayWorkload || access.NodeID != "" || entry.input.Mode != "command" {
		return nil
	}
	command, err := entry.product.Command(entry.input)
	if err != nil {
		return err
	}
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return err
	}
	root := index[entry.owned.Binding.RootID]
	if root == nil {
		return errStagedUnconfigured
	}
	for key, raw := range root.CommandReceipts {
		if !isStagedReceiptKey(key) {
			continue
		}
		retained, err := workloadReceiptCommand(raw)
		if err != nil {
			return err
		}
		if workloadCommandCollision(stagedReceipt{Command: retained}, entry.actor.PrincipalID, command.CommandID) {
			return apiErrorf(409, "command_conflict")
		}
	}
	scope := s.stagedScopes[entry.owned.Binding.ScopeID]
	if scope != nil && scope.pending != nil && workloadCommandCollision(scope.pending.receipt, entry.actor.PrincipalID, command.CommandID) {
		return apiErrorf(409, "command_conflict")
	}
	return nil
}

func workloadCommandCollision(receipt stagedReceipt, principal, commandID string) bool {
	_, workload := domainWorkloadID(receipt.Command.PrincipalID)
	return workload && receipt.Command.CommandID == commandID && receipt.Command.PrincipalID != principal
}

func workloadReceiptCommand(raw interface{}) (stagedCommand, error) {
	if receipt, ok := raw.(stagedReceipt); ok {
		return receipt.Command, nil
	}
	if value, ok := raw.(map[string]interface{}); ok {
		var command stagedCommand
		err := decodeStagedInternal(value["command"], &command)
		return command, err
	}
	var receipt stagedReceipt
	err := decodeStagedInternal(raw, &receipt)
	return receipt.Command, err
}
