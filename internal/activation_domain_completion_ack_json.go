// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// DomainCompletionAck is private host cleanup, never business actor authority.
type DomainCompletionAck struct {
	ContractRevision string `json:"contractRevision"`
	Epoch            string `json:"epoch"`
	LeaseID          string `json:"leaseId"`
	HostID           string `json:"hostId"`
	ChannelToken     string `json:"channelToken"`
	ResponseHash     string `json:"responseHash"`
	Disposition      string `json:"disposition"`
	PermitID         string `json:"permitId"`
}

// DecodeDomainCompletionAck accepts exactly one bounded versioned string envelope.
func DecodeDomainCompletionAck(raw []byte) (DomainControl, error) {
	var value DomainCompletionAck
	if len(raw) == 0 || len(raw) > 8192 {
		return DomainControl{}, fmt.Errorf("native completion acknowledgement byte bound")
	}
	if err := DecodeDomainJSON(raw, &value); err != nil {
		return DomainControl{}, err
	}
	if err := completionAckFields(raw); err != nil {
		return DomainControl{}, err
	}
	if value.ContractRevision != "native-completion-ack/1" || !domainValidHash(value.ResponseHash) {
		return DomainControl{}, fmt.Errorf("native completion acknowledgement version/hash invalid")
	}
	for _, id := range []string{value.Epoch, value.LeaseID, value.HostID} {
		if len(id) == 0 || len(id) > 512 {
			return DomainControl{}, fmt.Errorf("native completion acknowledgement identifier bound")
		}
	}
	if len(value.ChannelToken) < 32 || len(value.ChannelToken) > 4096 || len(value.PermitID) > 512 {
		return DomainControl{}, fmt.Errorf("native completion acknowledgement credential bound")
	}
	if value.Disposition != "handed-off" && value.Disposition != "irrevocably-discarded" {
		return DomainControl{}, fmt.Errorf("native completion acknowledgement disposition invalid")
	}
	if value.Disposition == "handed-off" && value.PermitID == "" {
		return DomainControl{}, fmt.Errorf("native completion acknowledgement permit absent")
	}
	return DomainControl{Action: "finish", Epoch: value.Epoch, LeaseID: value.LeaseID, HostID: value.HostID,
		ChannelToken: value.ChannelToken, ResponseHash: value.ResponseHash, Disposition: value.Disposition, PermitID: value.PermitID}, nil
}

func completionAckFields(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := DecodeDomainJSON(raw, &fields); err != nil {
		return err
	}
	if len(fields) != 8 {
		return fmt.Errorf("native completion acknowledgement fields absent")
	}
	allowed := map[string]bool{"contractRevision": true, "epoch": true, "leaseId": true, "hostId": true,
		"channelToken": true, "responseHash": true, "disposition": true, "permitId": true}
	for key, value := range fields {
		value = bytes.TrimSpace(value)
		if !allowed[key] || len(value) == 0 || value[0] != '"' {
			return fmt.Errorf("native completion acknowledgement requires strings")
		}
	}
	return nil
}
