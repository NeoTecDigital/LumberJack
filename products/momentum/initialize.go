// Written by Richard Christopher, Copyright 2026 Mindfull
package momentum

import (
	"fmt"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func initialize(p payload, owned engine.DomainOwnedScope, view engine.DomainView, actor string) (engine.DomainDelta, error) {
	if p.NodeID != owned.Binding.RootID {
		return engine.DomainDelta{}, fmt.Errorf("initialize only the bound workspace root")
	}
	root, _, err := checkedRecord(p.NodeID, owned, view)
	if err != nil {
		return engine.DomainDelta{}, err
	}
	owner := root.Metadata[owned.Layout.Fields["personalOwner"]]
	if owner != nil && owner != actor {
		return engine.DomainDelta{}, fmt.Errorf("workspace owner mismatch")
	}
	if root.Metadata[owned.Layout.Fields["defaultsVersion"]] == "1" {
		return engine.DomainDelta{Writes: []engine.DomainWrite{{NodeID: p.NodeID, Key: owned.Layout.Fields["defaultsVersion"], Value: "1"}}}, nil
	}
	if len(view.Records) != 1 {
		return engine.DomainDelta{}, fmt.Errorf("nonempty workspace requires explicit migration")
	}
	values := recordValues(payload{Title: "My workspace", Kind: "workspace"}, owned, actor)
	values[owned.Layout.Fields["personalOwner"]] = actor
	values[owned.Layout.Fields["defaultsVersion"]] = "1"
	delta := engine.DomainDelta{Writes: []engine.DomainWrite{}, Creates: []engine.DomainCreate{}}
	for _, field := range Fields {
		delta.Writes = append(delta.Writes, engine.DomainWrite{NodeID: p.NodeID, Key: owned.Layout.Fields[field], Value: values[owned.Layout.Fields[field]]})
	}
	delta.Creates, err = defaults(owned, view, actor)
	return delta, err
}

func defaults(owned engine.DomainOwnedScope, view engine.DomainView, actor string) ([]engine.DomainCreate, error) {
	rows := []struct{ title, kind string }{{"Inbox", "collection"}, {"Goals", "collection"}, {"Procedures", "collection"}, {"Documents", "collection"},
		{"Health", "category"}, {"Wealth", "category"}, {"Love", "category"}, {"Happiness", "category"}}
	result := make([]engine.DomainCreate, 0, len(rows))
	for _, row := range rows {
		item, err := create(payload{ParentID: owned.Binding.RootID, Title: row.title, Kind: row.kind}, owned, view, actor)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, nil
}
