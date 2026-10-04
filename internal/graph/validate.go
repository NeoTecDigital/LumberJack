// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// validateCommandShape refuses a malformed command before anything is looked at, and fills in the
// expectation maps a caller left out so the rest of the engine reads them without nil checks.
func validateCommandShape(cmd *Command) error {
	if !safeID(cmd.ID) {
		return invalidf("command id is required and must be a safe handle")
	}
	if strings.TrimSpace(cmd.Fingerprint) == "" {
		return invalidf("command fingerprint is required")
	}
	if len(cmd.Operations) == 0 {
		return invalidf("command must contain operations")
	}
	for key := range cmd.ResultMetadata {
		switch key {
		case "command_id", "revision", "changes", "replayed", "result_metadata":
			return invalidf("result_metadata key %q is server-owned", key)
		}
	}
	normalizeExpected(&cmd.Expected)
	for _, op := range cmd.Operations {
		if err := validateOperationShape(op); err != nil {
			return err
		}
	}
	return nil
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

// validateImmutable holds an entity's kind fixed after creation. Its id is fixed by construction:
// the record's id is always the operation's.
func validateImmutable(base, candidate *State, cmd Command) error {
	for _, op := range cmd.Operations {
		if op.Collection != CollectionEntities || op.Op != "put" {
			continue
		}
		old := base.Entities[op.ID]
		if old == nil {
			continue
		}
		if recordString(old, "kind") != recordString(candidate.Entities[op.ID], "kind") {
			return invalidf("entity %q cannot change its kind", op.ID)
		}
	}
	return nil
}

// validateState checks the whole candidate: identities, references, containment and geometry.
func validateState(state *State) error {
	for id, record := range state.Entities {
		if err := validateEntity(id, record); err != nil {
			return err
		}
	}
	for id, record := range state.Occurrences {
		if err := validateOccurrence(id, record, state); err != nil {
			return err
		}
	}
	if err := validateContainment(state); err != nil {
		return err
	}
	for id, record := range state.Edges {
		if err := validateEdge(id, record, state); err != nil {
			return err
		}
	}
	for id, record := range state.Views {
		if err := validateView(id, record, state); err != nil {
			return err
		}
	}
	return validateAliases(state)
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

func validateOccurrence(id string, record Record, state *State) error {
	if !semanticID(id) || recordString(record, "id") != id {
		return invalidf("occurrence %q id mismatch", id)
	}
	entity, scope := recordString(record, "entity_id"), recordString(record, "scope_id")
	if !semanticID(entity) {
		return invalidf("occurrence %q has invalid entity_id", id)
	}
	if _, ok := state.Entities[entity]; !ok {
		return invalidf("occurrence %q references missing entity %q", id, entity)
	}
	if !semanticID(scope) {
		return invalidf("occurrence %q requires a semantic scope_id", id)
	}
	if _, ok := state.Entities[scope]; !ok {
		return invalidf("occurrence %q references missing scope %q", id, scope)
	}
	if err := fixedGeometry(record["geometry"]); err != nil {
		return invalidf("occurrence %q geometry %v", id, err)
	}
	return nil
}

func validateEdge(id string, record Record, state *State) error {
	if !semanticID(id) || recordString(record, "id") != id {
		return invalidf("edge %q id mismatch", id)
	}
	for _, field := range []string{"source", "target", "scope_id"} {
		value := recordString(record, field)
		if !semanticID(value) {
			return invalidf("edge %q has invalid %s", id, field)
		}
		if _, ok := state.Entities[value]; !ok {
			return invalidf("edge %q references missing %s %q", id, field, value)
		}
	}
	if strings.TrimSpace(recordString(record, "relation")) == "" {
		return invalidf("edge %q missing relation", id)
	}
	return nil
}

func validateView(id string, record Record, state *State) error {
	if recordString(record, "id") != id {
		return invalidf("view %q id mismatch", id)
	}
	if err := validateViewRefs(id, "entity_ids", record["entity_ids"], state.Entities); err != nil {
		return err
	}
	return validateViewRefs(id, "occurrence_ids", record["occurrence_ids"], state.Occurrences)
}

func validateViewRefs(id, field string, raw json.RawMessage, table map[string]Record) error {
	if len(raw) == 0 {
		return nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return invalidf("view %q %s must be string ids", id, field)
	}
	for _, ref := range ids {
		if _, ok := table[ref]; !ok {
			return invalidf("view %q references missing %s", id, ref)
		}
	}
	return nil
}

func validateAliases(state *State) error {
	for alias, target := range state.Aliases {
		if !safeID(alias) || !safeID(target) {
			return invalidf("invalid alias")
		}
		_, entity := state.Entities[target]
		_, occurrence := state.Occurrences[target]
		if !entity && !occurrence {
			return invalidf("alias %q references missing target %q", alias, target)
		}
	}
	return nil
}

// validateContainment refuses a scope that contains itself through any chain of occurrences.
func validateContainment(state *State) error {
	adjacency := map[string][]string{}
	for _, occurrence := range state.Occurrences {
		scope := recordString(occurrence, "scope_id")
		adjacency[scope] = append(adjacency[scope], recordString(occurrence, "entity_id"))
	}
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
		for _, child := range adjacency[id] {
			if err := walk(child); err != nil {
				return err
			}
		}
		delete(visiting, id)
		visited[id] = true
		return nil
	}
	for id := range adjacency {
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
