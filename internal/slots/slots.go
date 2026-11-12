// Written by Richard Christopher, Copyright 2026 NeoTec, LLC

// Package slots is the storage behind the persisted keys a record carries that the engine does not
// type: extension slot keys, and keys nobody claims, kept as the bytes the state file held
// (docs/extension-api.md §4.5). It is internal to the module, so only core's record codec and the
// engine can reach a store: an extension reads and writes slots through extension.ReadTx.Slot and
// extension.Tx.SetSlot, which hold it to the keys it declared.
package slots

import (
	"encoding/json"
	"sort"
)

// Token is what core asks for before it hands out a node's store. Code outside the module cannot
// name it, so cannot ask.
type Token struct{ _ struct{} }

// Value is one key: the bytes it is written as, and the value decoded from them when a codec read
// it.
type Value struct {
	Raw        json.RawMessage
	Decoded    any
	HasDecoded bool
}

// Store is one record's slot keys.
type Store struct {
	values map[string]*Value
}

// Get answers a key's value.
func (s *Store) Get(key string) (*Value, bool) {
	value, ok := s.values[key]
	return value, ok
}

// SetRaw sets a key to bytes, dropping any decoded value.
func (s *Store) SetRaw(key string, raw json.RawMessage) {
	s.Set(key, &Value{Raw: raw})
}

// Set sets a key.
func (s *Store) Set(key string, value *Value) {
	if s.values == nil {
		s.values = map[string]*Value{}
	}
	s.values[key] = value
}

// Delete removes a key.
func (s *Store) Delete(key string) { delete(s.values, key) }

// Keys answers the keys held, sorted.
func (s *Store) Keys() []string {
	keys := make([]string, 0, len(s.values))
	for key := range s.values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Len is how many keys are held.
func (s *Store) Len() int { return len(s.values) }

// CopyFrom makes s hold exactly what other holds.
func (s *Store) CopyFrom(other *Store) {
	s.values = nil
	for key, value := range other.values {
		copied := *value
		s.Set(key, &copied)
	}
}
