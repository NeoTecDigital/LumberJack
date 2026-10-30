// Written by Richard Christopher, Copyright 2026 Mindfull
package momentum

import (
	"encoding/json"
	"fmt"
	"strings"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func decode(input engine.DomainInput) (envelope, error) {
	var request envelope
	if len(input.Body) > 65536 || engine.DecodeDomainJSON(input.Body, &request) != nil {
		return request, fmt.Errorf("bounded typed workspace envelope required")
	}
	if request.ContractRevision != Revision || request.Scope.Product != "momentum" || !text(request.Scope.AccountID, 200, false) {
		return request, fmt.Errorf("workspace scope/revision invalid")
	}
	keys := []string{"contractRevision", "scope"}
	if input.Mode == "command" {
		keys = append(keys, "commandId", "expectedRevision", "operation", "payload")
	}
	if exact(input.Body, keys) != nil || (input.Mode != "read" && input.Mode != "command") {
		return request, fmt.Errorf("workspace envelope fields invalid")
	}
	if input.Mode == "read" {
		return request, nil
	}
	if !text(request.CommandID, 100, false) || !validRevision(request.ExpectedRevision) {
		return request, fmt.Errorf("bounded command identity and explicit revision required")
	}
	var raw map[string]json.RawMessage
	_ = engine.DecodeDomainJSON(input.Body, &raw)
	return request, validatePayload(request.Operation, request.Payload, raw["payload"])
}

func validRevision(value string) bool {
	if !strings.HasPrefix(value, "lj.owned/v1:") || len(value) != len("lj.owned/v1:")+64 {
		return false
	}
	return strings.Trim(value[len("lj.owned/v1:"):], "0123456789abcdef") == ""
}

func exact(raw []byte, fields []string) error {
	var keys map[string]json.RawMessage
	if engine.DecodeDomainJSON(raw, &keys) != nil || len(keys) != len(fields) {
		return fmt.Errorf("workspace exact fields required")
	}
	for _, key := range fields {
		if keys[key] == nil || string(keys[key]) == "null" {
			return fmt.Errorf("workspace required field missing")
		}
	}
	return nil
}

func validatePayload(operation string, p payload, raw []byte) error {
	if operation == Initialize {
		if !text(p.NodeID, 200, false) {
			return fmt.Errorf("workspace root required")
		}
		return exact(raw, []string{"nodeId"})
	}
	identity := "nodeId"
	if operation == Create {
		identity = "parentId"
	} else if operation != Update {
		return fmt.Errorf("workspace operation unsupported")
	}
	if exact(raw, []string{identity, "title", "kind", "content"}) != nil || !validKind(p.Kind) || !text(p.Title, 200, false) || !text(p.Content, 32768, true) {
		return fmt.Errorf("workspace editable fields invalid")
	}
	if operation == Create && !text(p.ParentID, 200, false) || operation == Update && !text(p.NodeID, 200, false) {
		return fmt.Errorf("workspace target required")
	}
	return nil
}
