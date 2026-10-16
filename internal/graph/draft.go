// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

// slot is one member's value: a record, or an alias's target, or — when it is not live — nothing.
type slot struct {
	record Record
	target string
	live   bool
}

// text is the JSON text a live slot is stored under on its node.
func (s slot) text() string {
	if s.record != nil {
		return recordText(s.record)
	}
	return recordText(s.target)
}

// draft is a command's candidate: the base state with the command's changes laid OVER it.
//
// Nothing in the base is written and nothing in it is copied, so a command costs what it touches
// rather than what the graph holds, and a refused command leaves the base exactly as it was. Only
// an accepted draft is absorbed.
type draft struct {
	base  *State
	slots map[key]slot
	// order is the members the command's operations settled, first touch first.
	order []key
	// carried is the scopes whose topology revision the engine advanced without the command
	// having written them. They are stored, but they are not changes and get no history entry.
	carried []key
	// placed and members index the occurrences the draft holds, as the base's index does its own.
	placed   map[string]placement
	members  map[string]map[string]string
	revision uint64
}

func newDraft(base *State) *draft {
	return &draft{
		base:     base,
		slots:    map[key]slot{},
		placed:   map[string]placement{},
		members:  map[string]map[string]string{},
		revision: base.Revision + 1,
	}
}

func (d *draft) slotOf(k key) slot {
	if held, touched := d.slots[k]; touched {
		return held
	}
	return d.base.slotOf(k)
}

func (d *draft) record(collection, id string) Record {
	return d.slotOf(key{collection, id}).record
}

// set settles a member at a value, or at nothing.
func (d *draft) set(k key, next slot) {
	if _, touched := d.slots[k]; !touched {
		d.order = append(d.order, k)
	}
	d.slots[k] = next
	if k.collection != CollectionOccurrences {
		return
	}
	if was, held := d.placed[k.id]; held {
		dropNested(d.members, was.scope, k.id)
		delete(d.placed, k.id)
	}
	if next.live {
		at := placementOf(next.record)
		d.placed[k.id] = at
		setNested(d.members, at.scope, k.id, at.entity)
	}
}

// revisionOf is the revision a put continues from: the draft's own when it has already written
// the record, and otherwise the base's — which is a tombstone's when the record was deleted.
func (d *draft) revisionOf(k key) uint64 {
	if held, touched := d.slots[k]; touched && held.live {
		return recordUint(held.record, "revision")
	}
	return d.base.revisionOf(k)
}

// predecessor is the record a put replaces, reaching through a delete: the live one, the one this
// same command deleted, or the value a tombstone kept. It is what engine-owned fields carry from.
func (d *draft) predecessor(k key) Record {
	if held := d.slotOf(k); held.live {
		return held.record
	}
	if record := d.base.record(k.collection, k.id); record != nil {
		return record
	}
	return d.base.buried(k)
}

// bump advances a scope's topology revision. A scope the command did not write is copied before
// it is changed: the base's record is shared with readers and is never written in place.
func (d *draft) bump(scope string) {
	k := key{CollectionEntities, scope}
	held, touched := d.slots[k]
	if !touched {
		record := d.base.Entities[scope]
		if record == nil {
			return
		}
		held = slot{record: cloneRecord(record), live: true}
		d.slots[k] = held
		d.carried = append(d.carried, k)
	}
	if held.live {
		setUint(held.record, "topology_revision", d.base.topologyOf(scope)+1)
	}
}

// settled is every member the draft stores: what the command changed, then what the engine carried.
func (d *draft) settled() []key {
	out := make([]key, 0, len(d.order)+len(d.carried))
	out = append(out, d.order...)
	return append(out, d.carried...)
}

// contained is the entities a scope holds in the draft: the base's members the command left
// alone, and the draft's own.
func (d *draft) contained(scope string) []string {
	out := make([]string, 0, len(d.members[scope]))
	for occurrence, entity := range d.base.index.members[scope] {
		if _, touched := d.slots[key{CollectionOccurrences, occurrence}]; !touched {
			out = append(out, entity)
		}
	}
	for _, entity := range d.members[scope] {
		out = append(out, entity)
	}
	return out
}

// replaced is the entities whose membership the command changed: where a cycle could now start.
func (d *draft) replaced() []string {
	out := []string{}
	for id, at := range d.placed {
		was := d.base.Occurrences[id]
		if was == nil || placementOf(was) != at {
			out = append(out, at.entity)
		}
	}
	return out
}
