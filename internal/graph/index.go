// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import "encoding/json"

// index is what lets a command be checked against what it touches instead of against everything.
//
// It answers two questions the collections cannot without a full scan: which records NAME a given
// record (so a delete re-checks exactly its referrers), and which entities each scope contains (so
// a membership change walks only the containment it could close into a cycle, and an entity's
// parents are read rather than recomputed). It is derived: a load rebuilds it, and a command
// advances it with the state.
type index struct {
	// referrers is, for a record, the members that name it.
	referrers map[key]map[key]struct{}
	// members is scope id -> occurrence id -> the entity that occurrence places in the scope.
	members map[string]map[string]string
	// scopes is entity id -> occurrence id -> the scope that occurrence places it in.
	scopes map[string]map[string]string
}

func newIndex() *index {
	return &index{
		referrers: map[key]map[key]struct{}{},
		members:   map[string]map[string]string{},
		scopes:    map[string]map[string]string{},
	}
}

// placement is the membership an occurrence states: this entity is in this scope.
type placement struct{ entity, scope string }

func placementOf(record Record) placement {
	return placement{entity: recordString(record, "entity_id"), scope: recordString(record, "scope_id")}
}

// namedBy is every record a member names, which is every record whose deletion could orphan it.
// An alias names both collections its target may be in; either one satisfies it.
func namedBy(k key, held slot) []key {
	switch k.collection {
	case CollectionOccurrences:
		at := placementOf(held.record)
		return []key{{CollectionEntities, at.entity}, {CollectionEntities, at.scope}}
	case CollectionEdges:
		out := make([]key, 0, 3)
		for _, field := range []string{"source", "target", "scope_id"} {
			out = append(out, key{CollectionEntities, recordString(held.record, field)})
		}
		return out
	case CollectionViews:
		out := refKeys(CollectionEntities, held.record["entity_ids"])
		return append(out, refKeys(CollectionOccurrences, held.record["occurrence_ids"])...)
	case CollectionAliases:
		return []key{{CollectionEntities, held.target}, {CollectionOccurrences, held.target}}
	}
	return nil
}

func refKeys(collection string, raw json.RawMessage) []key {
	var ids []string
	if len(raw) == 0 || json.Unmarshal(raw, &ids) != nil {
		return nil
	}
	out := make([]key, 0, len(ids))
	for _, id := range ids {
		out = append(out, key{collection, id})
	}
	return out
}

func (ix *index) add(k key, held slot) {
	for _, named := range namedBy(k, held) {
		if ix.referrers[named] == nil {
			ix.referrers[named] = map[key]struct{}{}
		}
		ix.referrers[named][k] = struct{}{}
	}
	if k.collection == CollectionOccurrences {
		at := placementOf(held.record)
		setNested(ix.members, at.scope, k.id, at.entity)
		setNested(ix.scopes, at.entity, k.id, at.scope)
	}
}

func (ix *index) drop(k key, held slot) {
	for _, named := range namedBy(k, held) {
		delete(ix.referrers[named], k)
		if len(ix.referrers[named]) == 0 {
			delete(ix.referrers, named)
		}
	}
	if k.collection == CollectionOccurrences {
		at := placementOf(held.record)
		dropNested(ix.members, at.scope, k.id)
		dropNested(ix.scopes, at.entity, k.id)
	}
}

func setNested(table map[string]map[string]string, outer, inner, value string) {
	if table[outer] == nil {
		table[outer] = map[string]string{}
	}
	table[outer][inner] = value
}

func dropNested(table map[string]map[string]string, outer, inner string) {
	delete(table[outer], inner)
	if len(table[outer]) == 0 {
		delete(table, outer)
	}
}
