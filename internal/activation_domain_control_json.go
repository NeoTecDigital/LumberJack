// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
)

// DecodeDomainControlJSON rejects cross-action fields before any owner/lifetime lookup.
func DecodeDomainControlJSON(raw []byte, input *DomainControl) error {
	if err := DecodeDomainJSON(raw, input); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := DecodeDomainJSON(raw, &keys); err != nil {
		return err
	}
	required, optional, err := domainControlKeys(input.Action)
	if err != nil {
		return err
	}
	for _, key := range required {
		if _, present := keys[key]; !present {
			return fmt.Errorf("native control field absent")
		}
	}
	for key := range keys {
		if !domainContains(required, key) && !domainContains(optional, key) {
			return fmt.Errorf("native control cross-action field denied")
		}
	}
	return nil
}
func domainControlKeys(action string) ([]string, []string, error) {
	base := []string{"action", "epoch", "hostId", "channelToken"}
	if action == "close" {
		return append(base, "keys"), []string{"leaseId"}, nil
	}
	base = append(base, "leaseId")
	switch action {
	case "adopt", "receive":
		return base, nil, nil
	case "handoff":
		return append(base, "proof"), nil, nil
	case "validate":
		return append(base, "leaseBinding", "intent", "principalId", "sessionId", "validUntil"), nil, nil
	case "finish":
		return append(base, "responseHash", "disposition"), []string{"permitId"}, nil
	}
	return nil, nil, fmt.Errorf("invalid native control action")
}
