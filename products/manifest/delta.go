// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func canonicalBody(raw []byte) ([]byte, error) {
	var value interface{}
	if err := engine.DecodeDomainJSON(raw, &value); err != nil {
		return nil, err
	}
	return engine.CanonicalDomainJSON(value)
}
func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func (Adapter) Build(input engine.DomainInput, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainDelta, error) {
	request, p, err := decode(input)
	if err != nil {
		return engine.DomainDelta{}, err
	}
	if err = validateGraph(owned, view); err != nil {
		return engine.DomainDelta{}, err
	}
	if strings.HasSuffix(request.Operation, ".define") {
		return define(request.Operation, p, owned, view)
	}
	switch request.Operation {
	case "associate.role.attach", "associate.role.detach":
		return updateRefs(p.AssociateID, "roleIds", p.RoleID, request.Operation == "associate.role.detach", owned, view)
	case "role.requirement.attach":
		return updateRefs(p.RoleID, "requirementIds", p.ItemID, false, owned, view)
	case "role.function.attach":
		return updateRefs(p.RoleID, "functionIds", p.ItemID, false, owned, view)
	case "item.context.link":
		return updateContexts(p, owned, view)
	}
	return engine.DomainDelta{}, fmt.Errorf("unsupported native operation")
}
func define(operation string, p payload, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainDelta, error) {
	if view.AllocateID == nil || view.CreateACL == nil {
		return engine.DomainDelta{}, fmt.Errorf("native allocation/owner create authority absent")
	}
	kind := strings.TrimSuffix(strings.TrimPrefix(operation, "context."), ".define")
	id, err := view.AllocateID()
	if err != nil {
		return engine.DomainDelta{}, err
	}
	acl, err := view.CreateACL(kind)
	if err != nil {
		return engine.DomainDelta{}, err
	}
	values := map[string]interface{}{owned.Layout.Fields["accountId"]: owned.Binding.AccountID, owned.Layout.Fields["label"]: p.Label, view.ACLMetadataKey: acl}
	switch kind {
	case "role":
		values[owned.Layout.Fields["requirementIds"]] = []string{}
		values[owned.Layout.Fields["functionIds"]] = []string{}
	case "requirement", "function":
		values[owned.Layout.Fields["contextLinks"]] = []link{}
	case "record", "category":
		values[owned.Layout.Fields["kind"]] = p.Kind
	}
	return engine.DomainDelta{Creates: []engine.DomainCreate{{ID: id, ParentID: owned.Binding.RootID, Kind: nativeKind(owned, kind), Name: id, Metadata: values}}}, nil
}
func updateRefs(id, field, target string, detach bool, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainDelta, error) {
	refs, err := referenceList(view.Records[id].Metadata[owned.Layout.Fields[field]])
	if err != nil {
		return engine.DomainDelta{}, err
	}
	next := make([]string, 0, len(refs)+1)
	for _, ref := range refs {
		if !detach || ref != target {
			next = append(next, ref)
		}
	}
	if !detach && !contains(next, target) {
		next = append(next, target)
	}
	return engine.DomainDelta{Writes: []engine.DomainWrite{{NodeID: id, Key: owned.Layout.Fields[field], Value: next}}}, nil
}
func updateContexts(p payload, owned engine.DomainOwnedScope, view engine.DomainView) (engine.DomainDelta, error) {
	links, err := contextList(view.Records[p.ItemID].Metadata[owned.Layout.Fields["contextLinks"]])
	if err != nil {
		return engine.DomainDelta{}, err
	}
	present := false
	for _, value := range links {
		if value == p.ContextLink {
			present = true
		}
	}
	if !present {
		links = append(links, p.ContextLink)
	}
	// Native source values remain JSON-like, never product structs inside metadata.
	raw, _ := json.Marshal(links)
	var values interface{}
	if err = engine.DecodeDomainJSON(raw, &values); err != nil {
		return engine.DomainDelta{}, err
	}
	return engine.DomainDelta{Writes: []engine.DomainWrite{{NodeID: p.ItemID, Key: owned.Layout.Fields["contextLinks"], Value: values}}}, nil
}
func referenceList(value interface{}) ([]string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var refs []string
	if err = engine.DecodeDomainJSON(raw, &refs); err != nil || refs == nil {
		return nil, fmt.Errorf("required native reference array invalid")
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		if ref == "" || seen[ref] {
			return nil, fmt.Errorf("native references invalid/duplicate")
		}
		seen[ref] = true
	}
	return refs, nil
}
func contextList(value interface{}) ([]link, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var links []link
	if err = engine.DecodeDomainJSON(raw, &links); err != nil || links == nil {
		return nil, fmt.Errorf("required native contexts invalid")
	}
	seen := map[link]bool{}
	for _, ref := range links {
		if ref.TargetID == "" || !contains([]string{"record", "category"}, ref.Mode) || !contains(contextKinds, ref.Kind) || seen[ref] {
			return nil, fmt.Errorf("native contexts invalid/duplicate")
		}
		seen[ref] = true
	}
	return links, nil
}
