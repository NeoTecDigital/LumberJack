// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func checkActivationJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := activationJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("invalid Activation JSON")
	}
	return nil
}

func activationJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return fmt.Errorf("Activation JSON exceeds nesting limit")
	}
	value, err := decoder.Token()
	if err != nil {
		return err
	}
	if value == nil {
		return fmt.Errorf("Activation JSON cannot contain null")
	}
	if delimiter, ok := value.(json.Delim); ok {
		return activationJSONContainer(decoder, delimiter, depth+1)
	}
	return nil
}

func activationJSONContainer(decoder *json.Decoder, delimiter json.Delim, depth int) error {
	if delimiter != '{' && delimiter != '[' {
		return fmt.Errorf("invalid Activation JSON container")
	}
	keys := map[string]bool{}
	for decoder.More() {
		if err := activationJSONKey(decoder, delimiter, keys); err != nil {
			return err
		}
		if err := activationJSONValue(decoder, depth); err != nil {
			return err
		}
	}
	_, err := decoder.Token()
	return err
}

func activationJSONKey(decoder *json.Decoder, delimiter json.Delim, keys map[string]bool) error {
	if delimiter != '{' {
		return nil
	}
	key, err := decoder.Token()
	name, ok := key.(string)
	if err != nil || !ok || keys[name] {
		return fmt.Errorf("duplicate or invalid Activation JSON key")
	}
	keys[name] = true
	return nil
}

func DecodeActivationConfig(body []byte) (ActivationConfig, error) {
	var config ActivationConfig
	if err := strictActivationJSON(body, &config); err != nil {
		return config, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return config, fmt.Errorf("invalid Activation config")
	}
	for _, name := range []string{"verifierEndpoint", "channelToken", "audience", "issuer", "timeoutMs",
		"maxProofBytes", "maxBodyBytes", "maxResponseBytes", "maxLifetimeSeconds", "syntheticLoopbackOnly"} {
		if _, ok := fields[name]; !ok {
			return config, fmt.Errorf("missing required Activation config")
		}
	}
	// localHumanPreview is optional; strict decoding accepts only the typed bool.
	return config, ValidateActivationConfig(config)
}

func (scope *activationScope) UnmarshalJSON(body []byte) error {
	var wire struct {
		AccountID   string          `json:"accountId"`
		Product     string          `json:"product"`
		WorkspaceID json.RawMessage `json:"workspaceId"`
	}
	if err := strictActivationJSON(body, &wire); err != nil {
		return err
	}
	scope.AccountID, scope.Product = wire.AccountID, wire.Product
	if len(wire.WorkspaceID) > 0 {
		var id string
		if json.Unmarshal(wire.WorkspaceID, &id) != nil || id == "" {
			return fmt.Errorf("invalid Activation workspace")
		}
		scope.WorkspaceID = &id
	}
	return nil
}
