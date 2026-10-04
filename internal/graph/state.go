// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

// State is the graph decoded out of the forest: what a command is validated against, and what a
// candidate is built from. It shares nothing with the forest, so a candidate that fails leaves the
// forest exactly as it was.
type State struct {
	Revision    uint64
	Entities    map[string]Record
	Occurrences map[string]Record
	Edges       map[string]Record
	Views       map[string]Record
	Aliases     map[string]string
}

func newState() *State {
	return &State{
		Entities:    map[string]Record{},
		Occurrences: map[string]Record{},
		Edges:       map[string]Record{},
		Views:       map[string]Record{},
		Aliases:     map[string]string{},
	}
}

// clone copies every collection and every record map, so a put on the copy never reaches the base.
func (s *State) clone() *State {
	out := newState()
	out.Revision = s.Revision
	for _, collection := range recordCollections {
		source, target := s.collection(collection), out.collection(collection)
		for id, record := range source {
			target[id] = cloneRecord(record)
		}
	}
	for alias, target := range s.Aliases {
		out.Aliases[alias] = target
	}
	return out
}

// recordCollections are the collections whose members are Records; aliases are plain strings.
var recordCollections = []string{CollectionEntities, CollectionOccurrences, CollectionEdges, CollectionViews}

func validCollection(collection string) bool {
	return collection == CollectionAliases || isRecordCollection(collection)
}

func isRecordCollection(collection string) bool {
	for _, known := range recordCollections {
		if known == collection {
			return true
		}
	}
	return false
}

func (s *State) collection(collection string) map[string]Record {
	switch collection {
	case CollectionEntities:
		return s.Entities
	case CollectionOccurrences:
		return s.Occurrences
	case CollectionEdges:
		return s.Edges
	case CollectionViews:
		return s.Views
	}
	return nil
}

func (s *State) record(collection, id string) Record {
	table := s.collection(collection)
	if table == nil {
		return nil
	}
	return table[id]
}

func (s *State) put(collection, id string, record Record) {
	if table := s.collection(collection); table != nil {
		table[id] = record
	}
}

func (s *State) remove(collection, id string) {
	if collection == CollectionAliases {
		delete(s.Aliases, id)
		return
	}
	if table := s.collection(collection); table != nil {
		delete(table, id)
	}
}

// snapshot is the state as the API reports it.
func (s *State) snapshot() Snapshot {
	return Snapshot{
		Revision:    s.Revision,
		Entities:    s.Entities,
		Occurrences: s.Occurrences,
		Edges:       s.Edges,
		Views:       s.Views,
		Aliases:     s.Aliases,
	}
}

// scopesOf indexes which scopes each entity has an occurrence in, which is the entity's parentage.
func (s *State) scopesOf() map[string]map[string]struct{} {
	index := map[string]map[string]struct{}{}
	for _, occurrence := range s.Occurrences {
		entity, scope := recordString(occurrence, "entity_id"), recordString(occurrence, "scope_id")
		if index[entity] == nil {
			index[entity] = map[string]struct{}{}
		}
		index[entity][scope] = struct{}{}
	}
	return index
}
