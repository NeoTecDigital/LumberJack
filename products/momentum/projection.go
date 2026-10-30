// Written by Richard Christopher, Copyright 2026 Mindfull
package momentum

import (
	"encoding/json"
	"fmt"
	"sort"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func (Adapter) Project(requestID string, intent engine.DomainIntent, owned engine.DomainOwnedScope, view engine.DomainView) ([]byte, error) {
	actor := view.VerifiedAuthority
	if actor == nil || actor.Kind != "human" || actor.Scope != intent.Scope {
		return nil, fmt.Errorf("verified workspace projection actor required")
	}
	ids := make([]string, 0, len(view.Records))
	for id := range view.Records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	nodes := []map[string]interface{}{}
	for _, id := range ids {
		node, err := projectNode(id, intent, owned, view)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return engine.CanonicalDomainJSON(map[string]interface{}{"contractRevision": Revision, "requestId": requestID,
		"scope": intent.Scope, "revision": view.Revision, "principalId": actor.PrincipalID, "nodes": nodes})
}

func projectNode(id string, intent engine.DomainIntent, owned engine.DomainOwnedScope, view engine.DomainView) (map[string]interface{}, error) {
	record, kind, err := checkedRecord(id, owned, view)
	if err != nil {
		return nil, err
	}
	if !projected(id, kind, intent) {
		return nil, fmt.Errorf("workspace projection lacks field authority")
	}
	permission, err := writablePermission(record, view)
	if err != nil {
		return nil, err
	}
	result := map[string]interface{}{"id": id, "permission": permission}
	for _, field := range Fields {
		value, present := record.Metadata[owned.Layout.Fields[field]]
		if kind == "root" && !present {
			continue
		}
		if _, valid := value.(string); !valid {
			return nil, fmt.Errorf("workspace typed source field invalid")
		}
		result[field] = value
	}
	return result, nil
}

func writablePermission(record engine.DomainRecord, view engine.DomainView) (int, error) {
	var acl struct {
		Principals map[string]map[string]struct {
			Fields   []string `json:"fields"`
			Revision string   `json:"targetGrantRevision,omitempty"`
		} `json:"principals"`
	}
	raw, err := engine.CanonicalDomainJSON(record.Metadata[view.ACLMetadataKey])
	if err != nil {
		return 0, err
	}
	// ACL decoding here is projection only; actual policy remains the engine owner.
	if err = json.Unmarshal(raw, &acl); err != nil {
		return 0, err
	}
	actor := view.VerifiedAuthority
	for _, operation := range []string{Initialize, Create, Update} {
		grant, exists := acl.Principals[actor.PrincipalID][operation]
		if exists && (grant.Revision == "" || grant.Revision == actor.GrantRevision) && sameFields(grant.Fields, profile("work")) {
			return 1, nil // Never infer sharing/administration (legacy permission 2).
		}
	}
	return 0, nil
}

func projected(id, kind string, intent engine.DomainIntent) bool {
	for _, fields := range intent.Fields {
		if fields.Resource.ResourceID == id && fields.Resource.Kind == kind {
			return sameFields(fields.Fields, profile(kind))
		}
	}
	return false
}
