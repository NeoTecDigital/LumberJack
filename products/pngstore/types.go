// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"encoding/json"
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
)

const Revision = "png-native-store/0.1"
const WriteOperation = "png.store.write.define"

type Adapter struct{}
type Request struct {
	ContractRevision string             `json:"contractRevision"`
	Scope            engine.DomainScope `json:"scope"`
	CommandID        string             `json:"commandId,omitempty"`
	ExpectedRevision string             `json:"expectedRevision,omitempty"`
	Operation        string             `json:"operation,omitempty"`
	Action           string             `json:"action"`
	Query            Query              `json:"query"`
	Mutations        []Mutation         `json:"mutations"`
	References       []Reference        `json:"references"`
	Unique           []Unique           `json:"unique"`
	Result           json.RawMessage    `json:"result"`
}
type Query struct {
	Family  string   `json:"family"`
	Key     string   `json:"key"`
	Filters []Filter `json:"filters"`
	Limit   int      `json:"limit"`
	OrderBy []string `json:"order_by"`
	Fields  []string `json:"fields"`
}
type Filter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}
type Mutation struct {
	Family          string                 `json:"family"`
	Key             string                 `json:"key"`
	NativeID        string                 `json:"native_id"`
	ExpectedVersion string                 `json:"expected_version"`
	Data            map[string]interface{} `json:"data"`
	Patch           bool                   `json:"patch"`
}
type Reference struct {
	Family   string   `json:"family"`
	Key      string   `json:"key"`
	NativeID string   `json:"native_id"`
	Version  string   `json:"version"`
	Subtype  *string  `json:"subtype"`
	Fields   []string `json:"fields"`
}
type Unique struct {
	Family string                 `json:"family"`
	Fields map[string]interface{} `json:"fields"`
}
type Record struct {
	Family   string                 `json:"family"`
	Key      string                 `json:"key"`
	NativeID string                 `json:"native_id"`
	Version  string                 `json:"version"`
	Data     map[string]interface{} `json:"data"`
}

func decode(input engine.DomainInput) (Request, error) {
	var request Request
	err := engine.DecodeDomainJSON(input.Body, &request)
	if err != nil {
		return request, err
	}
	if request.ContractRevision != Revision || request.Action == "" {
		return request, fmt.Errorf("invalid native store contract")
	}
	if input.Mode == "command" && (request.Operation != WriteOperation || request.CommandID == "" || request.ExpectedRevision == "") {
		return request, fmt.Errorf("native command identity required")
	}
	if input.Mode != "read" && input.Mode != "command" {
		return request, fmt.Errorf("invalid native mode")
	}
	return request, nil
}

func ValidateLayout(owned engine.DomainOwnedScope, aclKey string) error {
	if err := validateCreateDefaults(owned.Layout.ApplicationCreateDefaults); err != nil {
		return err
	}
	if owned.Layout.Kinds["png_record"] == "" {
		return fmt.Errorf("explicit native store kind required")
	}
	seen := map[string]bool{aclKey: true}
	for _, name := range []string{"pngKey", "pngFamily", "pngData", "pngVersion"} {
		key := owned.Layout.Fields[name]
		if key == "" || seen[key] {
			return fmt.Errorf("explicit unique native store metadata fields required")
		}
		seen[key] = true
	}
	for _, op := range []string{"png.store.read", WriteOperation} {
		if owned.Layout.Routes[op].Target == "" || owned.Layout.Routes[op].Method != "POST" {
			return fmt.Errorf("explicit store routes required")
		}
		if len(owned.Layout.Profiles[op]["root"]) == 0 || len(owned.Layout.Profiles[op]["png_record"]) == 0 {
			return fmt.Errorf("explicit native store ACL field profiles required")
		}
	}
	return validateAssociateCarrier(owned, aclKey)
}
