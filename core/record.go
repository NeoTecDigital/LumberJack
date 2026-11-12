// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"github.com/NeoTecDigital/LumberJack/internal/compat"
	"github.com/NeoTecDigital/LumberJack/internal/slots"
)

// The record codec (docs/extension-api.md §7.1). A node record is the node's typed fields, its slot
// keys, and its children named by id. It is written in compat.RecordOrder — the order the builds
// that carried product fields on Node wrote it in — with each typed field encoded exactly as
// encoding/json encodes it and each slot key written as its bytes, then any other slot keys sorted,
// then "children". So a store those builds wrote re-encodes to the same bytes, and a key nobody
// claims survives as the bytes it was read as.
//
// It decodes number-exactly: every interface value keeps its literal as a json.Number.

// Slots hands the engine a node's slot store. Code outside the module cannot name the token, so
// cannot ask; an extension reaches slots through extension.ReadTx.Slot and Tx.SetSlot.
func (n *Node) Slots(_ slots.Token) *slots.Store { return &n.slots }

// Slots hands the engine the outbox's slot store.
func (o *Outbox) Slots(_ slots.Token) *slots.Store { return &o.slots }

// typedRecord is a node's typed fields alone: Children is shadowed by a field that is never set.
type typedRecord struct {
	*Node
	Children *struct{} `json:"children,omitempty"`
}

// recordShape is how a record decodes: its children are ids.
type recordShape struct {
	*Node
	Children []string `json:"children"`
}

var nodeTypedKeys = typedKeysOf(reflect.TypeOf(Node{}))

var outboxTypedKeys = typedKeysOf(reflect.TypeOf(Outbox{}))

// typedKeysOf is every key a struct type writes.
func typedKeysOf(structType reflect.Type) map[string]bool {
	keys := map[string]bool{}
	for index := 0; index < structType.NumField(); index++ {
		field := structType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		keys[name] = true
	}
	return keys
}

// EncodeRecord writes one node record.
func EncodeRecord(node *Node, children []string) ([]byte, error) {
	typed, err := json.Marshal(typedRecord{Node: node})
	if err != nil {
		return nil, err
	}
	encodedChildren, err := json.Marshal(children)
	if err != nil {
		return nil, err
	}
	return orderedObject(typed, &node.slots, compat.RecordOrder, "children", encodedChildren)
}

// DecodeRecord reads one node record. Keys the node does not type go to its slot store as the bytes
// the record held.
func DecodeRecord(raw []byte) (*Node, []string, error) {
	shape := recordShape{Node: &Node{}}
	if err := decodeNumbers(raw, &shape); err != nil {
		return nil, nil, err
	}
	if err := keepUntyped(raw, &shape.Node.slots, nodeTypedKeys, "children"); err != nil {
		return nil, nil, err
	}
	return shape.Node, shape.Children, nil
}

// outboxTyped is Outbox without its codec.
type outboxTyped Outbox

// MarshalJSON writes the outbox in compat.OutboxOrder, its slot keys in place.
func (o *Outbox) MarshalJSON() ([]byte, error) {
	typed, err := json.Marshal((*outboxTyped)(o))
	if err != nil {
		return nil, err
	}
	return orderedObject(typed, &o.slots, compat.OutboxOrder, "", nil)
}

// UnmarshalJSON reads the outbox, keeping the keys it does not type in its slot store.
func (o *Outbox) UnmarshalJSON(raw []byte) error {
	var typed outboxTyped
	if err := decodeNumbers(raw, &typed); err != nil {
		return err
	}
	*o = Outbox(typed)
	return keepUntyped(raw, &o.slots, outboxTypedKeys, "")
}

// orderedObject merges a typed object's keys with a slot store's in the legacy order: the order's
// keys first, then typed keys the order does not name, in their own order, then other slot keys
// sorted, then the trailing key when there is one.
func orderedObject(typed []byte, store *slots.Store, order []string, trailing string, trailingValue []byte) ([]byte, error) {
	keys, values, err := objectPairs(typed)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteByte('{')
	written := map[string]bool{}
	emit := func(key string, value []byte) {
		if written[key] {
			return
		}
		if len(written) > 0 {
			out.WriteByte(',')
		}
		encodedKey, _ := json.Marshal(key)
		out.Write(encodedKey)
		out.WriteByte(':')
		out.Write(value)
		written[key] = true
	}
	for _, key := range order {
		if value, typedKey := values[key]; typedKey {
			emit(key, value)
		} else if slot, held := store.Get(key); held {
			emit(key, slot.Raw)
		}
	}
	for _, key := range keys {
		emit(key, values[key])
	}
	for _, key := range store.Keys() {
		slot, _ := store.Get(key)
		emit(key, slot.Raw)
	}
	if trailing != "" {
		emit(trailing, trailingValue)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// objectPairs splits a JSON object into its keys, in order, and their values as bytes.
func objectPairs(object []byte) ([]string, map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(object))
	if open, err := decoder.Token(); err != nil || open != json.Delim('{') {
		return nil, nil, fmt.Errorf("a record is not a JSON object")
	}
	var keys []string
	values := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, nil, err
		}
		key, _ := token.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, nil, err
		}
		if _, repeated := values[key]; !repeated {
			keys = append(keys, key)
		}
		values[key] = value
	}
	return keys, values, nil
}

// keepUntyped puts every key of a record its type does not hold into the slot store, as bytes.
func keepUntyped(raw []byte, store *slots.Store, typed map[string]bool, structural string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	untyped := make([]string, 0, len(fields))
	for key := range fields {
		if !typed[key] && key != structural {
			untyped = append(untyped, key)
		}
	}
	sort.Strings(untyped)
	for _, key := range untyped {
		store.SetRaw(key, fields[key])
	}
	return nil
}

// decodeNumbers decodes with every number in an interface value kept as its literal, and refuses
// trailing data the way json.Unmarshal does.
func decodeNumbers(raw []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid character after top-level value")
	}
	return nil
}

// nestedShape is a node of the nested shape the builds before the node table wrote: its children
// are nodes, inline.
type nestedShape struct {
	*Node
	Children map[string]json.RawMessage `json:"children"`
}

// DecodeNested reads a forest in the nested shape. A node reached by two paths is read twice, once
// per occurrence, as the nested file wrote it; Canonicalize rejoins the occurrences.
func DecodeNested(raw []byte) (*Node, error) {
	shape := nestedShape{Node: &Node{}}
	if err := decodeNumbers(raw, &shape); err != nil {
		return nil, err
	}
	if err := keepUntyped(raw, &shape.Node.slots, nodeTypedKeys, "children"); err != nil {
		return nil, err
	}
	if shape.Children == nil {
		return shape.Node, nil
	}
	shape.Node.Children = make(map[string]*Node, len(shape.Children))
	for key, value := range shape.Children {
		if string(value) == "null" {
			shape.Node.Children[key] = nil
			continue
		}
		child, err := DecodeNested(value)
		if err != nil {
			return nil, err
		}
		shape.Node.Children[key] = child
	}
	return shape.Node, nil
}
