// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import "encoding/json"

// State is the graph decoded out of the forest and KEPT: what a command is validated against. It
// shares nothing with the forest's nodes, so a command that is refused has touched neither.
//
// A Record held here is never written in place. A command replaces the records it changes, which
// is what lets a snapshot hand the same records to a reader that is still encoding them after the
// forest has been let go.
type State struct {
	Revision    uint64
	Entities    map[string]Record
	Occurrences map[string]Record
	Edges       map[string]Record
	Views       map[string]Record
	Aliases     map[string]string
	// Tombstones are the deleted records, by collection and id. They are in no collection.
	Tombstones map[key]Tombstone
	index      *index
}

// key names one member of one collection. Entity and occurrence ids may collide, so an id alone
// names nothing.
type key struct{ collection, id string }

// lookup is what a validator may ask of a graph: the base state answers it, and so does a draft.
type lookup interface {
	record(collection, id string) Record
}

func newState() *State {
	return &State{
		Entities:    map[string]Record{},
		Occurrences: map[string]Record{},
		Edges:       map[string]Record{},
		Views:       map[string]Record{},
		Aliases:     map[string]string{},
		Tombstones:  map[key]Tombstone{},
		index:       newIndex(),
	}
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

// slotOf is a member as the state holds it: live with its value, or absent.
func (s *State) slotOf(k key) slot {
	if k.collection == CollectionAliases {
		target, ok := s.Aliases[k.id]
		return slot{target: target, live: ok}
	}
	record := s.record(k.collection, k.id)
	return slot{record: record, live: record != nil}
}

// revisionOf is the revision an expectation is checked against: the live record's, the one a
// tombstone kept, or zero for an id that has never existed.
func (s *State) revisionOf(k key) uint64 {
	if record := s.record(k.collection, k.id); record != nil {
		return recordUint(record, "revision")
	}
	return s.Tombstones[k].Revision
}

// buried is the value a deleted record last held, or nil when the id has no tombstone.
func (s *State) buried(k key) Record {
	tomb, ok := s.Tombstones[k]
	if !ok {
		return nil
	}
	record, err := parseRecord(tomb.Prior)
	if err != nil {
		return nil
	}
	return record
}

// topologyOf is a scope's topology revision, which survives the scope's deletion like its revision.
func (s *State) topologyOf(id string) uint64 {
	if record := s.Entities[id]; record != nil {
		return recordUint(record, "topology_revision")
	}
	return recordUint(s.buried(key{CollectionEntities, id}), "topology_revision")
}

// kindOf is the kind an entity id is held to: the live entity's, or its tombstone's.
func (s *State) kindOf(id string) (string, bool) {
	if record := s.Entities[id]; record != nil {
		return recordString(record, "kind"), true
	}
	tomb, ok := s.Tombstones[key{CollectionEntities, id}]
	return tomb.Kind, ok
}

// entomb is the tombstone deleting k would leave, and false when k is not live.
func (s *State) entomb(k key) (Tombstone, bool) {
	held := s.slotOf(k)
	if !held.live {
		return Tombstone{}, false
	}
	tomb := Tombstone{Prior: json.RawMessage(held.text())}
	if k.collection != CollectionAliases {
		tomb.Revision = recordUint(held.record, "revision")
	}
	if k.collection == CollectionEntities {
		tomb.Kind = recordString(held.record, "kind")
	}
	return tomb, true
}

// absorb makes an accepted draft the state: every member the command settled replaces what was
// there, the index follows, and a member that was deleted leaves its tombstone.
func (s *State) absorb(d *draft) {
	for _, k := range d.settled() {
		next := d.slots[k]
		if held := s.slotOf(k); held.live {
			s.index.drop(k, held)
		}
		if tomb, ok := s.entomb(k); ok && !next.live {
			s.Tombstones[k] = tomb
		}
		s.store(k, next)
	}
	s.Revision = d.revision
}

// store writes one settled member. A live one clears the tombstone it was recreated over.
func (s *State) store(k key, next slot) {
	if !next.live {
		if k.collection == CollectionAliases {
			delete(s.Aliases, k.id)
		} else {
			delete(s.collection(k.collection), k.id)
		}
		return
	}
	delete(s.Tombstones, k)
	if k.collection == CollectionAliases {
		s.Aliases[k.id] = next.target
	} else {
		s.collection(k.collection)[k.id] = next.record
	}
	s.index.add(k, next)
}

// reindex rebuilds the index from the collections, which is what a load ends with.
func (s *State) reindex() {
	s.index = newIndex()
	for _, collection := range recordCollections {
		for id, record := range s.collection(collection) {
			s.index.add(key{collection, id}, slot{record: record, live: true})
		}
	}
	for id, target := range s.Aliases {
		s.index.add(key{CollectionAliases, id}, slot{target: target, live: true})
	}
}

// snapshot is the state as the API reports it. The collection maps are COPIED, because the caller
// encodes them after it has let the forest go and the next command writes the originals; the
// records in them are shared, and are never written in place. Tombstones are not reported.
func (s *State) snapshot() Snapshot {
	out := Snapshot{Revision: s.Revision, Aliases: make(map[string]string, len(s.Aliases))}
	out.Entities = copyRecords(s.Entities)
	out.Occurrences = copyRecords(s.Occurrences)
	out.Edges = copyRecords(s.Edges)
	out.Views = copyRecords(s.Views)
	for alias, target := range s.Aliases {
		out.Aliases[alias] = target
	}
	return out
}

func copyRecords(source map[string]Record) map[string]Record {
	out := make(map[string]Record, len(source))
	for id, record := range source {
		out[id] = record
	}
	return out
}
