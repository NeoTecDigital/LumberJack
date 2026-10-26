// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package manifest

import (
	"encoding/json"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"strings"
)

type combinedAdapter struct{}

func (combinedAdapter) BindTargetInput(input engine.DomainInput) (engine.DomainTargetInput, error) {
	if isStore(input) {
		return (pngstore.Adapter{}).BindTargetInput(input)
	}
	return nil, nil
}

func (combinedAdapter) IncludeRetainedReceipts(input engine.DomainInput) (bool, error) {
	if isStore(input) {
		return (pngstore.Adapter{}).IncludeRetainedReceipts(input)
	}
	return false, nil
}

func isStore(input engine.DomainInput) bool {
	var data struct {
		ContractRevision string `json:"contractRevision"`
	}
	_ = json.Unmarshal(input.Body, &data)
	return data.ContractRevision == pngstore.Revision
}
func (combinedAdapter) NativeCreates(input engine.DomainInput, owned engine.DomainOwnedScope, id string) bool {
	if id == owned.Binding.RootID {
		return false
	}
	if !isStore(input) {
		command, err := (Adapter{}).Command(input)
		return err == nil && strings.HasSuffix(command.Operation, ".define")
	}
	var request pngstore.Request
	if engine.DecodeDomainJSON(input.Body, &request) != nil {
		return false
	}
	for _, mutation := range request.Mutations {
		if mutation.NativeID == id {
			return false
		}
	}
	return input.Mode == "command"
}
func (combinedAdapter) Resolve(input engine.DomainInput, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainIntent, error) {
	if isStore(input) {
		return (pngstore.Adapter{}).Resolve(input, owned, view)
	}
	return (Adapter{}).Resolve(input, owned, legacyView(owned, view))
}
func (combinedAdapter) Command(input engine.DomainInput) (engine.DomainCommand, error) {
	if isStore(input) {
		return (pngstore.Adapter{}).Command(input)
	}
	return (Adapter{}).Command(input)
}
func (combinedAdapter) Build(input engine.DomainInput, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainDelta, error) {
	if isStore(input) {
		return (pngstore.Adapter{}).Build(input, owned, view)
	}
	return (Adapter{}).Build(input, owned, legacyView(owned, view))
}
func (combinedAdapter) Project(id string, intent engine.DomainIntent, owned engine.DomainOwnedScope, view engine.DomainView) ([]byte, error) {
	return (Adapter{}).Project(id, intent, owned, legacyView(owned, view))
}
func (combinedAdapter) ProjectInput(id string, input engine.DomainInput, intent engine.DomainIntent, owned engine.DomainOwnedScope, view engine.DomainView) ([]byte, error) {
	if isStore(input) {
		return (pngstore.Adapter{}).ProjectInput(id, input, intent, owned, view)
	}
	return (Adapter{}).Project(id, intent, owned, legacyView(owned, view))
}
func legacyView(owned engine.DomainOwnedScope, view engine.DomainView) engine.DomainView {
	filtered := map[string]engine.DomainRecord{}
	for id, record := range view.Records {
		if record.Kind != owned.Layout.Kinds["png_record"] {
			filtered[id] = record
		}
	}
	view.Records = filtered
	return view
}
func (combinedAdapter) TargetFields(input engine.DomainInput, owned engine.DomainOwnedScope, record engine.DomainRecord) []string {
	if !isStore(input) {
		return nil
	}
	return pngstore.TargetFields(input, owned, record)
}
func (combinedAdapter) PublicFields(kind string, keys []string, owned engine.DomainOwnedScope) ([]string, error) {
	if kind == owned.Layout.Kinds["png_record"] {
		return (pngstore.Adapter{}).PublicFields(kind, keys, owned)
	}
	return (Adapter{}).PublicFields(kind, keys, owned)
}
