// Written by Richard Christopher, Copyright 2026 Mindfull
package momentum

import (
	"fmt"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func (Adapter) ProjectCommand(input engine.DomainInput, owned engine.DomainOwnedScope, retained engine.DomainRetainedReceipt) (interface{}, error) {
	request, err := decode(input)
	if err != nil {
		return nil, err
	}
	if retained.Receipt.Command.CommandID != request.CommandID || retained.Receipt.Command.AccountID != request.Scope.AccountID {
		return nil, fmt.Errorf("workspace retained result binding mismatch")
	}
	id := request.Payload.NodeID
	if request.Operation == Create {
		id, err = createdID(retained, owned)
	}
	if err != nil || id == "" {
		return nil, fmt.Errorf("workspace retained result absent")
	}
	path := owned.Binding.RootID
	if id != path {
		path += "/" + id
	}
	return map[string]interface{}{"id": id, "path": path}, nil
}

func createdID(retained engine.DomainRetainedReceipt, owned engine.DomainOwnedScope) (string, error) {
	id := ""
	for _, target := range retained.Receipt.Targets {
		if target.Kind != owned.Layout.Kinds["work"] || !includes(target.Fields, owned.Layout.Fields["createdBy"]) {
			continue
		}
		if id != "" && id != target.NodeID {
			return "", fmt.Errorf("ambiguous workspace creation receipt")
		}
		id = target.NodeID
	}
	return id, nil
}

func includes(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
