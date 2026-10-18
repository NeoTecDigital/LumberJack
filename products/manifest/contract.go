// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package manifest

import (
	"encoding/json"
	"fmt"
	"sort"
	"unicode/utf8"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

const Revision = "manifest-associates/0.1"

type Adapter struct{}

func New() engine.DomainProduct { return Adapter{} }

type envelope struct {
	ContractRevision string             `json:"contractRevision"`
	Scope            engine.DomainScope `json:"scope"`
	CommandID        string             `json:"commandId,omitempty"`
	ExpectedRevision string             `json:"expectedRevision,omitempty"`
	Operation        string             `json:"operation,omitempty"`
	Payload          json.RawMessage    `json:"payload,omitempty"`
}
type payload struct {
	Label       string `json:"label"`
	Kind        string `json:"kind"`
	AssociateID string `json:"associateId"`
	RoleID      string `json:"roleId"`
	ItemID      string `json:"itemId"`
	ItemKind    string `json:"itemKind"`
	ContextLink link   `json:"contextLink"`
}
type link struct {
	Mode     string `json:"mode"`
	Kind     string `json:"kind"`
	TargetID string `json:"targetId"`
}

var operations = []string{"role.define", "requirement.define", "function.define", "associate.role.attach", "associate.role.detach", "role.requirement.attach", "role.function.attach", "context.record.define", "context.category.define", "item.context.link"}

func decode(input engine.DomainInput) (envelope, payload, error) {
	var request envelope
	if err := engine.DecodeDomainJSON(input.Body, &request); err != nil {
		return request, payload{}, err
	}
	if request.ContractRevision != Revision || request.Scope.AccountID == "" || request.Scope.Product != "manifest" {
		return request, payload{}, fmt.Errorf("invalid Manifest envelope")
	}
	var keys map[string]json.RawMessage
	if err := engine.DecodeDomainJSON(input.Body, &keys); err != nil {
		return request, payload{}, err
	}
	if input.Mode == "read" {
		if len(keys) != 2 {
			return request, payload{}, fmt.Errorf("read envelope has extra fields")
		}
		return request, payload{}, nil
	}
	if input.Mode != "command" || len(keys) != 6 || request.CommandID == "" || request.ExpectedRevision == "" || !contains(operations, request.Operation) {
		return request, payload{}, fmt.Errorf("invalid command envelope")
	}
	p, err := decodePayload(request.Operation, request.Payload)
	return request, p, err
}
func decodePayload(operation string, raw []byte) (payload, error) {
	var values map[string]json.RawMessage
	if err := engine.DecodeDomainJSON(raw, &values); err != nil {
		return payload{}, err
	}
	required := payloadKeys(operation)
	if len(values) != len(required) {
		return payload{}, fmt.Errorf("payload fields mismatch")
	}
	for _, key := range required {
		if _, present := values[key]; !present {
			return payload{}, fmt.Errorf("payload field absent")
		}
	}
	var result payload
	if err := engine.DecodeDomainJSON(raw, &result); err != nil {
		return result, err
	}
	if value, present := values["label"]; present {
		var label interface{}
		if engine.DecodeDomainJSON(value, &label) != nil {
			return result, fmt.Errorf("label must be text")
		}
		if _, ok := label.(string); !ok {
			return result, fmt.Errorf("label must be text")
		}
	}
	if operation == "context.record.define" || operation == "context.category.define" {
		if !contains(contextKinds, result.Kind) {
			return result, fmt.Errorf("invalid context kind")
		}
	}
	if operation == "item.context.link" {
		if !contains([]string{"requirement", "function"}, result.ItemKind) || !contains([]string{"record", "category"}, result.ContextLink.Mode) || !contains(contextKinds, result.ContextLink.Kind) || result.ContextLink.TargetID == "" {
			return result, fmt.Errorf("invalid context link")
		}
	}
	for _, key := range required {
		if key == "label" || key == "contextLink" {
			continue
		}
		var text string
		if json.Unmarshal(values[key], &text) != nil || text == "" {
			return result, fmt.Errorf("invalid payload identifier")
		}
	}
	return result, nil
}
func payloadKeys(operation string) []string {
	switch operation {
	case "role.define", "requirement.define", "function.define":
		return []string{"label"}
	case "context.record.define", "context.category.define":
		return []string{"kind", "label"}
	case "associate.role.attach", "associate.role.detach":
		return []string{"associateId", "roleId"}
	case "role.requirement.attach", "role.function.attach":
		return []string{"roleId", "itemId"}
	case "item.context.link":
		return []string{"itemKind", "itemId", "contextLink"}
	}
	return nil
}

var contextKinds = []string{"standard", "policy", "procedure", "operation"}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func ValidateLayout(owned engine.DomainOwnedScope, aclKey string) error {
	requiredKinds := []string{"root", "associate", "role", "requirement", "function", "record", "category"}
	used := map[string]bool{}
	for _, kind := range requiredKinds {
		value := owned.Layout.Kinds[kind]
		if value == "" || used[value] {
			return fmt.Errorf("explicit unique native kinds required")
		}
		used[value] = true
	}
	used = map[string]bool{}
	for _, field := range []string{"accountId", "kind", "label", "roleIds", "requirementIds", "functionIds", "contextLinks", "defaultKey"} {
		value := owned.Layout.Fields[field]
		if value == "" || value == aclKey || used[value] || !utf8.ValidString(value) {
			return fmt.Errorf("explicit unique metadata field mapping required")
		}
		used[value] = true
	}
	for _, operation := range append([]string{"read"}, operations...) {
		route := owned.Layout.Routes[operation]
		if route.Method == "" || route.Target == "" || len(owned.Layout.Profiles[operation]) == 0 {
			return fmt.Errorf("explicit intent routes/profiles required")
		}
	}
	return validateReadProfiles(owned)
}
func validateReadProfiles(owned engine.DomainOwnedScope) error {
	for _, kind := range []string{"root", "associate", "role", "requirement", "function", "record", "category"} {
		if err := requireFields(owned.Layout.Profiles["read"][kind], append([]string{"id"}, publicRecordFields(kind)...)); err != nil {
			return err
		}
	}
	return nil
}
func nativeKind(owned engine.DomainOwnedScope, kind string) string { return owned.Layout.Kinds[kind] }
func semanticKind(owned engine.DomainOwnedScope, kind string) string {
	for key, value := range owned.Layout.Kinds {
		if kind == value {
			return key
		}
	}
	return ""
}
func (Adapter) Command(input engine.DomainInput) (engine.DomainCommand, error) {
	request, _, err := decode(input)
	return engine.DomainCommand{CommandID: request.CommandID, ExpectedRevision: request.ExpectedRevision, Operation: request.Operation}, err
}
func (Adapter) PublicFields(kind string, keys []string, owned engine.DomainOwnedScope) ([]string, error) {
	if semanticKind(owned, kind) == "" {
		return nil, fmt.Errorf("unmapped native kind")
	}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		field, err := publicField(owned, key)
		if err != nil {
			return nil, err
		}
		out = append(out, field)
	}
	sort.Strings(out)
	return out, nil
}
func publicField(owned engine.DomainOwnedScope, key string) (string, error) {
	if key == "children" {
		return key, nil
	}
	for field, value := range owned.Layout.Fields {
		if value == key {
			return field, nil
		}
	}
	return "", fmt.Errorf("delta attempted a non-public metadata field")
}
