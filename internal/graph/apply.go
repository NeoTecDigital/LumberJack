// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import "encoding/json"

// checkExpected compares every expectation the caller sent against the base.
func checkExpected(base *State, expected Expected) error {
	for id, want := range expected.Entities {
		if got := recordUint(base.Entities[id], "revision"); got != want {
			return staleConflict(CollectionEntities, id, want, got)
		}
	}
	for id, want := range expected.Occurrences {
		if got := recordUint(base.Occurrences[id], "revision"); got != want {
			return staleConflict(CollectionOccurrences, id, want, got)
		}
	}
	for id, want := range expected.Views {
		if got := recordUint(base.Views[id], "revision"); got != want {
			return staleConflict(CollectionViews, id, want, got)
		}
	}
	for id, want := range expected.Topology {
		if got := recordUint(base.Entities[id], "topology_revision"); got != want {
			return staleConflict("topology", id, want, got)
		}
	}
	return nil
}

// requireRecordExpected makes entity, occurrence and view writes NAME the version they replace.
// This is stricter than checking only the entries a caller happened to send: creation names
// revision 0, so an accidental upsert cannot silently overwrite a record.
func requireRecordExpected(base *State, cmd Command) error {
	for _, op := range cmd.Operations {
		expected := expectedFor(cmd.Expected, op.Collection)
		if expected == nil {
			continue
		}
		want, ok := expected[op.ID]
		if !ok {
			return conflictf(op.Collection, op.ID, "requires an expected revision")
		}
		if got := recordUint(base.record(op.Collection, op.ID), "revision"); got != want {
			return staleConflict(op.Collection, op.ID, want, got)
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
		if got := recordUint(base.Entities[id], "topology_revision"); got != want {
			return staleConflict("topology", id, want, got)
		}
	}
	return nil
}

// applyOperations plays the operations onto the candidate, in order, and reports what changed and
// which scopes' topology moved.
func applyOperations(candidate *State, cmd Command) ([]Change, map[string]struct{}, error) {
	changes := make([]Change, 0, len(cmd.Operations))
	scopes := map[string]struct{}{}
	for _, op := range cmd.Operations {
		if err := noteTopology(candidate, op, scopes); err != nil {
			return nil, nil, err
		}
		if err := applyOperation(candidate, op); err != nil {
			return nil, nil, err
		}
		changes = append(changes, Change{Collection: op.Collection, ID: op.ID, Op: op.Op})
	}
	return changes, scopes, nil
}

// noteTopology records which scopes an occurrence or edge operation changes the membership of.
// Geometry is occurrence-local: only a membership change invalidates a scope's topology, so
// independent drags do not conflict globally.
func noteTopology(candidate *State, op Operation, scopes map[string]struct{}) error {
	switch op.Collection {
	case CollectionOccurrences:
		old := candidate.Occurrences[op.ID]
		next, err := optionalRecord(op)
		if err != nil {
			return err
		}
		if membershipChanged(old, next) {
			addScope(scopes, old)
			addScope(scopes, next)
		}
	case CollectionEdges:
		addScope(scopes, candidate.Edges[op.ID])
		next, err := optionalRecord(op)
		if err != nil {
			return err
		}
		addScope(scopes, next)
	}
	return nil
}

func optionalRecord(op Operation) (Record, error) {
	if op.Op != "put" {
		return nil, nil
	}
	record, err := parseRecord(op.Value)
	if err != nil {
		return nil, invalidf("put %s/%s: %v", op.Collection, op.ID, err)
	}
	return record, nil
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
	for _, key := range []string{"scope_id", "entity_id", "view_id"} {
		if recordString(old, key) != recordString(next, key) {
			return true
		}
	}
	return false
}

func applyOperation(candidate *State, op Operation) error {
	if op.Collection == CollectionAliases {
		return applyAlias(candidate, op)
	}
	if op.Op == "delete" {
		candidate.remove(op.Collection, op.ID)
		return nil
	}
	record, err := parseRecord(op.Value)
	if err != nil {
		return invalidf("put %s/%s: %v", op.Collection, op.ID, err)
	}
	old := candidate.record(op.Collection, op.ID)
	setString(record, "id", op.ID)
	setUint(record, "revision", recordUint(old, "revision")+1)
	if op.Collection == CollectionEntities {
		carryTopologyRevision(old, record)
	}
	candidate.put(op.Collection, op.ID, record)
	return nil
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

func applyAlias(candidate *State, op Operation) error {
	if op.Op == "delete" {
		delete(candidate.Aliases, op.ID)
		return nil
	}
	var target string
	if err := json.Unmarshal(op.Value, &target); err != nil || !safeID(target) {
		return invalidf("alias %q must target a safe id string", op.ID)
	}
	candidate.Aliases[op.ID] = target
	return nil
}

// bumpTopology advances the counter of every scope whose membership changed and still exists. A
// deleted scope has no surviving record to carry one.
func bumpTopology(base, candidate *State, scopes map[string]struct{}) {
	for scopeID := range scopes {
		if scopeID == "" {
			continue
		}
		record, exists := candidate.Entities[scopeID]
		if !exists {
			continue
		}
		setUint(record, "topology_revision", recordUint(base.Entities[scopeID], "topology_revision")+1)
	}
}

// fillChangeRevisions reports the revision each put left its record at.
func fillChangeRevisions(candidate *State, changes []Change) {
	for i := range changes {
		if changes[i].Op != "put" {
			continue
		}
		changes[i].Revision = recordUint(candidate.record(changes[i].Collection, changes[i].ID), "revision")
	}
}
