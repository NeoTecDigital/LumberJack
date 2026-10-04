// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// operation is one operation with its put value decoded, once, before the graph is looked at.
type operation struct {
	Operation
	record Record // a put's value, in the collections that hold records
	target string // a put's value, for an alias
}

// prepare refuses a malformed command before anything is looked at, fills in the expectation maps
// a caller left out so the rest of the engine reads them without nil checks, and decodes every
// put value.
func prepare(cmd *Command) ([]operation, error) {
	if !safeID(cmd.ID) {
		return nil, invalidf("command id is required and must be a safe handle")
	}
	if strings.TrimSpace(cmd.Fingerprint) == "" {
		return nil, invalidf("command fingerprint is required")
	}
	if len(cmd.Operations) == 0 {
		return nil, invalidf("command must contain operations")
	}
	normalizeExpected(&cmd.Expected)
	ops := make([]operation, 0, len(cmd.Operations))
	for _, op := range cmd.Operations {
		if err := validateOperationShape(op); err != nil {
			return nil, err
		}
		parsed, err := parseOperation(op)
		if err != nil {
			return nil, err
		}
		ops = append(ops, parsed)
	}
	return ops, nil
}

func normalizeExpected(expected *Expected) {
	if expected.Entities == nil {
		expected.Entities = map[string]uint64{}
	}
	if expected.Occurrences == nil {
		expected.Occurrences = map[string]uint64{}
	}
	if expected.Views == nil {
		expected.Views = map[string]uint64{}
	}
	if expected.Topology == nil {
		expected.Topology = map[string]uint64{}
	}
}

func validateOperationShape(op Operation) error {
	if op.Op != "put" && op.Op != "delete" {
		return invalidf("unknown operation %q", op.Op)
	}
	if !validCollection(op.Collection) {
		return invalidf("unknown mutable collection %q", op.Collection)
	}
	if !safeID(op.ID) {
		return invalidf("invalid %s id", op.Collection)
	}
	if op.Op == "put" && len(op.Value) == 0 {
		return invalidf("put %s/%s requires value", op.Collection, op.ID)
	}
	if op.Op == "delete" && len(op.Value) != 0 {
		return invalidf("delete %s/%s cannot include value", op.Collection, op.ID)
	}
	return nil
}

func parseOperation(op Operation) (operation, error) {
	out := operation{Operation: op}
	if op.Op != "put" {
		return out, nil
	}
	if op.Collection == CollectionAliases {
		if err := json.Unmarshal(op.Value, &out.target); err != nil || !safeID(out.target) {
			return out, invalidf("alias %q must target a safe id string", op.ID)
		}
		return out, nil
	}
	record, err := parseRecord(op.Value)
	if err != nil {
		return out, invalidf("put %s/%s: %v", op.Collection, op.ID, err)
	}
	out.record = record
	return out, matchValueID(op, record)
}

// matchValueID holds a value that states an id to the operation's. The engine used to overwrite a
// different one silently, which stored a record under an id its author had not named.
func matchValueID(op Operation, record Record) error {
	stated, present := record["id"]
	if !present || recordString(record, "id") == op.ID {
		return nil
	}
	return invalidf("put %s/%s: value.id %s differs from the operation id %q", op.Collection, op.ID, clip(stated), op.ID)
}

// clip bounds how much of a caller's value an error message repeats.
func clip(raw json.RawMessage) string {
	const limit = 96
	if len(raw) <= limit {
		return string(raw)
	}
	return string(raw[:limit]) + "..."
}

// validateDraft checks what the command touched: every member it left live, every member that
// names one it deleted, the kinds it may not change, and — because containment is the one rule no
// single record can answer — the cycles its membership changes could have closed.
func validateDraft(d *draft) error {
	for _, k := range d.order {
		held := d.slots[k]
		if !held.live {
			if err := validateReferrers(d, k); err != nil {
				return err
			}
			continue
		}
		if err := validateKind(d, k, held); err != nil {
			return err
		}
		if err := validateMember(k, held, d); err != nil {
			return err
		}
	}
	return findCycle(d.replaced(), d.contained)
}

// validateReferrers re-checks the members that named a deleted record and that the command did not
// itself rewrite. The ones it rewrote are checked as themselves.
func validateReferrers(d *draft, deleted key) error {
	for source := range d.base.index.referrers[deleted] {
		if _, touched := d.slots[source]; touched {
			continue
		}
		if err := validateMember(source, d.base.slotOf(source), d); err != nil {
			return err
		}
	}
	return nil
}

// validateKind holds an entity's kind fixed for as long as its id has existed, through a delete.
// Its id is fixed by construction: the record's id is always the operation's.
func validateKind(d *draft, k key, held slot) error {
	if k.collection != CollectionEntities {
		return nil
	}
	was, known := d.base.kindOf(k.id)
	if now := recordString(held.record, "kind"); known && was != now {
		return invalidf("entity %q cannot change its kind from %q to %q", k.id, was, now)
	}
	return nil
}

// validateState checks a whole graph. It runs once, when the graph is decoded out of the forest;
// after that every command is checked against what it touches.
func validateState(state *State) error {
	for _, collection := range recordCollections {
		for id, record := range state.collection(collection) {
			if err := validateMember(key{collection, id}, slot{record: record, live: true}, state); err != nil {
				return err
			}
		}
	}
	for alias, target := range state.Aliases {
		if err := validateAlias(alias, target, state); err != nil {
			return err
		}
	}
	scopes := make([]string, 0, len(state.index.members))
	for scope := range state.index.members {
		scopes = append(scopes, scope)
	}
	return findCycle(scopes, state.contained)
}

// contained is the entities a scope holds.
func (s *State) contained(scope string) []string {
	out := make([]string, 0, len(s.index.members[scope]))
	for _, entity := range s.index.members[scope] {
		out = append(out, entity)
	}
	return out
}

func validateMember(k key, held slot, graph lookup) error {
	switch k.collection {
	case CollectionEntities:
		return validateEntity(k.id, held.record)
	case CollectionOccurrences:
		return validateOccurrence(k.id, held.record, graph)
	case CollectionEdges:
		return validateEdge(k.id, held.record, graph)
	case CollectionViews:
		return validateView(k.id, held.record, graph)
	case CollectionAliases:
		return validateAlias(k.id, held.target, graph)
	}
	return nil
}

// validateEntity is the identity rule: a 64-lowercase-hex id the record carries, and a kind.
func validateEntity(id string, record Record) error {
	if !semanticID(id) || recordString(record, "id") != id {
		return invalidf("entity %q must carry its 64 lowercase hex id", id)
	}
	if strings.TrimSpace(recordString(record, "kind")) == "" {
		return invalidf("entity %q missing kind", id)
	}
	return nil
}

func validateOccurrence(id string, record Record, graph lookup) error {
	if !semanticID(id) || recordString(record, "id") != id {
		return invalidf("occurrence %q id mismatch", id)
	}
	entity, scope := recordString(record, "entity_id"), recordString(record, "scope_id")
	if !semanticID(entity) {
		return invalidf("occurrence %q has invalid entity_id", id)
	}
	if graph.record(CollectionEntities, entity) == nil {
		return invalidf("occurrence %q references missing entity %q", id, entity)
	}
	if !semanticID(scope) {
		return invalidf("occurrence %q requires a semantic scope_id", id)
	}
	if graph.record(CollectionEntities, scope) == nil {
		return invalidf("occurrence %q references missing scope %q", id, scope)
	}
	if err := fixedGeometry(record["geometry"]); err != nil {
		return invalidf("occurrence %q geometry %v", id, err)
	}
	return nil
}

func validateEdge(id string, record Record, graph lookup) error {
	if !semanticID(id) || recordString(record, "id") != id {
		return invalidf("edge %q id mismatch", id)
	}
	for _, field := range []string{"source", "target", "scope_id"} {
		value := recordString(record, field)
		if !semanticID(value) {
			return invalidf("edge %q has invalid %s", id, field)
		}
		if graph.record(CollectionEntities, value) == nil {
			return invalidf("edge %q references missing %s %q", id, field, value)
		}
	}
	if strings.TrimSpace(recordString(record, "relation")) == "" {
		return invalidf("edge %q missing relation", id)
	}
	return nil
}

func validateView(id string, record Record, graph lookup) error {
	if recordString(record, "id") != id {
		return invalidf("view %q id mismatch", id)
	}
	if err := validateViewRefs(id, "entity_ids", CollectionEntities, record, graph); err != nil {
		return err
	}
	return validateViewRefs(id, "occurrence_ids", CollectionOccurrences, record, graph)
}

func validateViewRefs(id, field, collection string, record Record, graph lookup) error {
	raw := record[field]
	if len(raw) == 0 {
		return nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return invalidf("view %q %s must be string ids", id, field)
	}
	for _, ref := range ids {
		if graph.record(collection, ref) == nil {
			return invalidf("view %q references missing %s", id, ref)
		}
	}
	return nil
}

func validateAlias(alias, target string, graph lookup) error {
	if !safeID(alias) || !safeID(target) {
		return invalidf("invalid alias")
	}
	if graph.record(CollectionEntities, target) == nil && graph.record(CollectionOccurrences, target) == nil {
		return invalidf("alias %q references missing target %q", alias, target)
	}
	return nil
}

// findCycle refuses a scope that contains itself through any chain of occurrences. It walks the
// containment reachable from starts and no further: a graph that had no cycle can only have gained
// one through a membership the command changed, and such a cycle passes through that entity.
func findCycle(starts []string, contained func(string) []string) error {
	visiting, visited := map[string]bool{}, map[string]bool{}
	var walk func(string) error
	walk = func(id string) error {
		if visiting[id] {
			return invalidf("containment cycle at %q", id)
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		for _, child := range contained(id) {
			if err := walk(child); err != nil {
				return err
			}
		}
		delete(visiting, id)
		visited[id] = true
		return nil
	}
	for _, id := range starts {
		if err := walk(id); err != nil {
			return err
		}
	}
	return nil
}

// fixedGeometry is an object of integers: x, y, width, height and scale, the last three positive.
// Fractions are refused rather than rounded, so two clients never disagree about a placement.
func fixedGeometry(raw json.RawMessage) error {
	if len(raw) == 0 {
		return invalidf("is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var geometry map[string]json.Number
	if err := decoder.Decode(&geometry); err != nil {
		return invalidf("must be an object of integer thousandths/millionths")
	}
	for _, key := range []string{"x", "y", "width", "height", "scale"} {
		number, ok := geometry[key]
		if !ok {
			return invalidf("missing %s", key)
		}
		if _, err := strconv.ParseInt(number.String(), 10, 64); err != nil {
			return invalidf("%s must be an integer", key)
		}
	}
	for _, key := range []string{"width", "height", "scale"} {
		if value, _ := strconv.ParseInt(geometry[key].String(), 10, 64); value <= 0 {
			return invalidf("%s must be positive", key)
		}
	}
	return nil
}
