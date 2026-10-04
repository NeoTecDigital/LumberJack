// Written by Richard Christopher, Copyright 2026 Richard Christopher

// Package graph is the command engine over Lumberjack's live forest.
//
// Entities, occurrences, edges, views and aliases are nodes under one `graph` root of the forest,
// changed only through all-or-nothing commands that name the revisions they replace, and journaled
// on that root. There is no store of its own: the forest's one lock covers a command, the forest's
// writer makes it durable, and the forest's state file is the only file.
package graph

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Record is a stored object as raw JSON. The engine owns `id`, `revision` and `topology_revision`;
// every other field is the caller's and is kept byte for byte.
type Record map[string]json.RawMessage

// Command is one all-or-nothing batch. ID is the caller's idempotency handle: the same id with the
// same payload replays the stored result, and the same id with a different payload is a conflict.
type Command struct {
	ID                string                     `json:"id"`
	Fingerprint       string                     `json:"fingerprint"`
	ClientFingerprint string                     `json:"client_fingerprint,omitempty"`
	Actor             string                     `json:"actor,omitempty"`
	Expected          Expected                   `json:"expected"`
	Operations        []Operation                `json:"operations"`
	ResultMetadata    map[string]json.RawMessage `json:"result_metadata,omitempty"`
}

// Expected names the revisions a command was written against. Zero names a record that does not
// exist yet, so a creation cannot silently overwrite.
type Expected struct {
	Entities    map[string]uint64 `json:"entities"`
	Occurrences map[string]uint64 `json:"occurrences"`
	Views       map[string]uint64 `json:"views"`
	Topology    map[string]uint64 `json:"topology"`
}

// Operation is one put or delete in a command.
type Operation struct {
	Op         string          `json:"op"`
	Collection string          `json:"collection"`
	ID         string          `json:"id"`
	Value      json.RawMessage `json:"value,omitempty"`
}

// Change is one record a command touched, with the revision a put left it at.
type Change struct {
	Collection string `json:"collection"`
	ID         string `json:"id"`
	Revision   uint64 `json:"revision,omitempty"`
	Op         string `json:"op"`
}

// Result is what a command answers, and what its receipt replays.
type Result struct {
	CommandID      string                     `json:"command_id"`
	Revision       uint64                     `json:"revision"`
	Changes        []Change                   `json:"changes"`
	Replayed       bool                       `json:"replayed"`
	ResultMetadata map[string]json.RawMessage `json:"result_metadata,omitempty"`
}

// Receipt is the durable record of one accepted command.
type Receipt struct {
	Fingerprint       string `json:"fingerprint"`
	ClientFingerprint string `json:"client_fingerprint,omitempty"`
	PayloadDigest     string `json:"payload_digest"`
	Actor             string `json:"actor"`
	At                string `json:"at"`
	Result            Result `json:"result"`
}

// Event is one journal entry: the revision a command produced and what it changed.
type Event struct {
	Revision  uint64   `json:"revision"`
	CommandID string   `json:"command_id"`
	Actor     string   `json:"actor"`
	At        string   `json:"at"`
	Changes   []Change `json:"changes"`
}

// EventsPage is one page of the journal. Next is the `since` that fetches the following page, and
// is absent on the last one.
type EventsPage struct {
	Events []Event `json:"events"`
	Next   *uint64 `json:"next,omitempty"`
}

// Snapshot is the whole graph at one revision.
type Snapshot struct {
	Revision    uint64            `json:"revision"`
	Entities    map[string]Record `json:"entities"`
	Occurrences map[string]Record `json:"occurrences"`
	Edges       map[string]Record `json:"edges"`
	Views       map[string]Record `json:"views"`
	Aliases     map[string]string `json:"aliases"`
}

// The mutable collections, in the order they are reported.
const (
	CollectionEntities    = "entities"
	CollectionOccurrences = "occurrences"
	CollectionEdges       = "edges"
	CollectionViews       = "views"
	CollectionAliases     = "aliases"
)

var (
	// ErrConflict marks a command that disagreed with the current revisions, or reused an id.
	ErrConflict = errors.New("graph revision conflict")
	// ErrInvalid marks a command that is malformed or would leave the graph invalid.
	ErrInvalid = errors.New("invalid graph command")
)

// Conflict says exactly what a stale command disagreed with, so the 409 can name it.
type Conflict struct {
	Collection string
	ID         string
	Expected   uint64
	Actual     uint64
	// Stale is true when Expected and Actual are the disagreement; false when the conflict is a
	// missing expectation or a reused command id, where the numbers mean nothing.
	Stale   bool
	Message string
}

func (c *Conflict) Error() string {
	if c.Stale {
		return fmt.Sprintf("%s %q expected %d, current %d", c.Collection, c.ID, c.Expected, c.Actual)
	}
	return fmt.Sprintf("%s %q %s", c.Collection, c.ID, c.Message)
}

// Is lets errors.Is(err, ErrConflict) hold for every Conflict.
func (c *Conflict) Is(target error) bool { return target == ErrConflict }

func staleConflict(collection, id string, expected, actual uint64) error {
	return &Conflict{Collection: collection, ID: id, Expected: expected, Actual: actual, Stale: true}
}

func conflictf(collection, id, format string, args ...interface{}) error {
	return &Conflict{Collection: collection, ID: id, Message: fmt.Sprintf(format, args...)}
}

func invalidf(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
