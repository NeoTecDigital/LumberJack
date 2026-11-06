// Written by Richard Christopher, Copyright 2026 Mindfull
package momentum

import (
	"fmt"
	"time"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func (Adapter) Build(input engine.DomainInput, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainDelta, error) {
	request, err := decode(input)
	if err != nil {
		return engine.DomainDelta{}, err
	}
	actor := view.VerifiedAuthority
	if actor == nil || actor.Kind != "human" || actor.Scope != request.Scope || actor.PrincipalID == "" {
		return engine.DomainDelta{}, fmt.Errorf("verified current workspace actor required")
	}
	if request.Operation == Initialize {
		return initialize(request.Payload, owned, view, actor.PrincipalID)
	}
	root := view.Records[owned.Binding.RootID]
	if root.Metadata[owned.Layout.Fields["defaultsVersion"]] != "1" {
		return engine.DomainDelta{}, fmt.Errorf("workspace initialization required")
	}
	if request.Operation == Update {
		return update(request.Payload, owned, view)
	}
	created, err := create(request.Payload, owned, view, actor.PrincipalID)
	return engine.DomainDelta{Creates: []engine.DomainCreate{created}}, err
}

func create(p payload, owned engine.DomainOwnedScope, view engine.DomainView, actor string) (engine.DomainCreate, error) {
	if view.AllocateID == nil || view.CreateACL == nil {
		return engine.DomainCreate{}, fmt.Errorf("native workspace allocation/ACL required")
	}
	id, err := view.AllocateID()
	if err != nil {
		return engine.DomainCreate{}, err
	}
	acl, err := view.CreateACL("work")
	if err != nil {
		return engine.DomainCreate{}, err
	}
	values := recordValues(p, owned, actor)
	values[view.ACLMetadataKey] = acl
	return engine.DomainCreate{ID: id, ParentID: p.ParentID, Kind: owned.Layout.Kinds["work"], Name: id, Metadata: values}, nil
}

func recordValues(p payload, owned engine.DomainOwnedScope, actor string) map[string]interface{} {
	values := map[string]interface{}{"accountId": owned.Binding.AccountID, "parentId": p.ParentID,
		"title": p.Title, "kind": p.Kind, "content": p.Content, "createdBy": actor,
		"createdAt": time.Now().UTC().Format(time.RFC3339Nano), "personalOwner": "", "defaultsVersion": ""}
	result := map[string]interface{}{}
	for key, value := range values {
		result[owned.Layout.Fields[key]] = value
	}
	return result
}

func update(p payload, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainDelta, error) {
	if p.NodeID == owned.Binding.RootID || p.Kind == "workspace" {
		return engine.DomainDelta{}, fmt.Errorf("workspace identity cannot be rewritten")
	}
	if _, _, err := checkedRecord(p.NodeID, owned, view); err != nil {
		return engine.DomainDelta{}, err
	}
	values := map[string]string{"title": p.Title, "kind": p.Kind, "content": p.Content}
	writes := []engine.DomainWrite{}
	for _, key := range []string{"title", "kind", "content"} {
		writes = append(writes, engine.DomainWrite{NodeID: p.NodeID, Key: owned.Layout.Fields[key], Value: values[key]})
	}
	return engine.DomainDelta{Writes: writes}, nil
}
