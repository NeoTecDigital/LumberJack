// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

// checkExpected compares every expectation the caller sent against the base. A deleted record is
// still at the revision its tombstone kept, so a writer that last saw it alive — or never saw it
// at all — does not match a record that has since been recreated.
func checkExpected(base *State, expected Expected) error {
	for _, collection := range []string{CollectionEntities, CollectionOccurrences, CollectionViews} {
		for id, want := range expectedFor(expected, collection) {
			if got := base.revisionOf(key{collection, id}); got != want {
				return staleConflict(collection, id, want, got)
			}
		}
	}
	for id, want := range expected.Topology {
		if got := base.topologyOf(id); got != want {
			return staleConflict("topology", id, want, got)
		}
	}
	return nil
}

// requireRecordExpected makes entity, occurrence and view writes NAME the version they replace.
// This is stricter than checking only the entries a caller happened to send: creation names
// revision 0 and re-creation names the tombstone's, so an accidental upsert cannot silently
// overwrite a record. The values themselves were compared by checkExpected.
func requireRecordExpected(expected Expected, ops []operation) error {
	for _, op := range ops {
		named := expectedFor(expected, op.Collection)
		if named == nil {
			continue
		}
		if _, ok := named[op.ID]; !ok {
			return conflictf(op.Collection, op.ID, "requires an expected revision")
		}
	}
	return nil
}

// expectedFor is the expectation map a collection's writes must appear in, or nil for the
// collections governed by topology instead.
func expectedFor(expected Expected, collection string) map[string]uint64 {
	switch collection {
	case CollectionEntities:
		return expected.Entities
	case CollectionOccurrences:
		return expected.Occurrences
	case CollectionViews:
		return expected.Views
	}
	return nil
}

// requireTopologyExpected makes a membership or edge change name the topology revision of every
// scope it touches.
func requireTopologyExpected(base *State, expected Expected, scopes map[string]struct{}) error {
	for id := range scopes {
		if id == "" {
			continue
		}
		want, ok := expected.Topology[id]
		if !ok {
			return conflictf("topology", id, "requires an expected topology revision for a membership or edge change")
		}
		if got := base.topologyOf(id); got != want {
			return staleConflict("topology", id, want, got)
		}
	}
	return nil
}

// applyOperations plays the operations onto the draft, in order, and reports what changed and
// which scopes' topology moved. Every value was decoded by prepare, so nothing here can refuse.
func applyOperations(d *draft, ops []operation) ([]Change, map[string]struct{}) {
	changes := make([]Change, 0, len(ops))
	scopes := map[string]struct{}{}
	for _, op := range ops {
		noteTopology(d, op, scopes)
		applyOperation(d, op)
		changes = append(changes, Change{Collection: op.Collection, ID: op.ID, Op: op.Op})
	}
	return changes, scopes
}

// noteTopology records which scopes an occurrence or edge operation changes the membership of.
// Geometry is occurrence-local: only a membership change invalidates a scope's topology, so
// independent drags do not conflict globally.
func noteTopology(d *draft, op operation, scopes map[string]struct{}) {
	old := d.record(op.Collection, op.ID)
	switch op.Collection {
	case CollectionOccurrences:
		if membershipChanged(old, op.record) {
			addScope(scopes, old)
			addScope(scopes, op.record)
		}
	case CollectionEdges:
		addScope(scopes, old)
		addScope(scopes, op.record)
	}
}

func addScope(scopes map[string]struct{}, record Record) {
	if record != nil {
		scopes[recordString(record, "scope_id")] = struct{}{}
	}
}

func membershipChanged(old, next Record) bool {
	if old == nil || next == nil {
		return true
	}
	for _, field := range []string{"scope_id", "entity_id", "view_id"} {
		if recordString(old, field) != recordString(next, field) {
			return true
		}
	}
	return false
}

func applyOperation(d *draft, op operation) {
	k := key{op.Collection, op.ID}
	switch {
	case op.Op == "delete":
		d.set(k, slot{})
	case op.Collection == CollectionAliases:
		d.set(k, slot{target: op.target, live: true})
	default:
		record := op.record
		setString(record, "id", op.ID)
		setUint(record, "revision", d.revisionOf(k)+1)
		if op.Collection == CollectionEntities {
			carryTopologyRevision(d.predecessor(k), record)
		}
		d.set(k, slot{record: record, live: true})
	}
}

// carryTopologyRevision keeps the engine-owned counter across a put. A caller that wrote an entity
// back without it used to erase it, resetting every topology expectation on that scope to zero —
// so the value is always the engine's, whatever the caller sent.
func carryTopologyRevision(old, next Record) {
	delete(next, "topology_revision")
	if old == nil {
		return
	}
	if prior, ok := old["topology_revision"]; ok {
		next["topology_revision"] = prior
	}
}

// bumpTopology advances the counter of every scope whose membership changed and still exists. A
// deleted scope has no surviving record to carry one.
func bumpTopology(d *draft, scopes map[string]struct{}) {
	for scopeID := range scopes {
		if scopeID != "" {
			d.bump(scopeID)
		}
	}
}

// fillChangeRevisions reports the revision each put left its record at.
func fillChangeRevisions(d *draft, changes []Change) {
	for i := range changes {
		if changes[i].Op != "put" {
			continue
		}
		changes[i].Revision = recordUint(d.record(changes[i].Collection, changes[i].ID), "revision")
	}
}
