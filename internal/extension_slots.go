// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/internal/slots"
)

// An extension's slots (docs/extension-api.md §4.5): the persisted keys it declared, on the root,
// on any node, or inside the root's outbox. It reaches only its own keys, only under a hold, and a
// write lands in the snapshot of the change that made it. A key is decoded once, on first read,
// through its Codec, and encoded only when it is set; a key nobody set since load is written back as
// the bytes the file held.

// slotKey finds the declaration of a key the owning extension may use at nodeID.
func (tx forestTx) slotKey(nodeID, key string) (extension.SlotKey, bool) {
	spec, ok := tx.server.extensionSpec(tx.owner)
	if !ok {
		return extension.SlotKey{}, false
	}
	var declared []extension.SlotKey
	switch {
	case nodeID == extension.OutboxSlots:
		declared = spec.Slot.OutboxKeys
	case tx.server.forest != nil && nodeID == tx.server.forest.ID:
		declared = append(append(declared, spec.Slot.RootKeys...), spec.Slot.NodeKeys...)
	default:
		declared = spec.Slot.NodeKeys
	}
	for _, slot := range declared {
		if slot.Name == key {
			return slot, true
		}
	}
	return extension.SlotKey{}, false
}

// slotStore is the store a key at nodeID lives in; create makes the outbox when it is missing.
func (tx forestTx) slotStore(nodeID string, create bool) *slots.Store {
	if nodeID == extension.OutboxSlots {
		if tx.server.forest.Correspondence == nil {
			if !create {
				return nil
			}
			tx.server.correspondenceState()
		}
		return tx.server.forest.Correspondence.Slots(slots.Token{})
	}
	node, found := tx.NodeByID(nodeID)
	if !found {
		return nil
	}
	return node.Slots(slots.Token{})
}

func (tx forestTx) Slot(nodeID, key string) (any, bool) {
	declared, ok := tx.slotKey(nodeID, key)
	if !ok {
		return nil, false
	}
	store := tx.slotStore(nodeID, false)
	if store == nil {
		return nil, false
	}
	value, held := store.Get(key)
	if !held {
		return nil, false
	}
	if value.HasDecoded {
		return value.Decoded, true
	}
	if declared.Codec == nil {
		return append(json.RawMessage(nil), value.Raw...), true
	}
	decoded, err := declared.Codec.Decode(value.Raw)
	if err != nil {
		return nil, false
	}
	value.Decoded, value.HasDecoded = decoded, true
	return decoded, true
}

func (tx forestTx) SetSlot(nodeID, key string, v any) error {
	declared, ok := tx.slotKey(nodeID, key)
	if !ok {
		return &extension.Error{Status: http.StatusForbidden, Message: fmt.Sprintf("slot %q is not declared by %q here", key, tx.owner)}
	}
	raw, err := encodeSlot(declared, v)
	if err != nil {
		return err
	}
	store := tx.slotStore(nodeID, true)
	if store == nil {
		return &extension.Error{Status: http.StatusNotFound, Message: "node not found: " + nodeID}
	}
	store.Set(key, &slots.Value{Raw: raw, Decoded: v, HasDecoded: declared.Codec != nil})
	return nil
}

func (tx forestTx) DeleteSlot(nodeID, key string) {
	if _, ok := tx.slotKey(nodeID, key); !ok {
		return
	}
	if store := tx.slotStore(nodeID, false); store != nil {
		store.Delete(key)
	}
}

// encodeSlot is a value's bytes: through the key's Codec, or the value itself as JSON when the key
// has none. Either way the bytes must be one valid JSON value.
func encodeSlot(declared extension.SlotKey, v any) (json.RawMessage, error) {
	var raw json.RawMessage
	switch {
	case declared.Codec != nil:
		encoded, err := declared.Codec.Encode(v)
		if err != nil {
			return nil, err
		}
		raw = encoded
	default:
		switch typed := v.(type) {
		case json.RawMessage:
			raw = typed
		case []byte:
			raw = typed
		default:
			return nil, &extension.Error{Status: http.StatusBadRequest, Message: "a slot without a codec takes json.RawMessage"}
		}
	}
	var compact json.RawMessage
	if err := json.Unmarshal(raw, &compact); err != nil {
		return nil, &extension.Error{Status: http.StatusBadRequest, Message: "a slot value is not one JSON value"}
	}
	return append(json.RawMessage(nil), raw...), nil
}

// extensionSpec is the Spec of an attached extension, by name.
func (server *Server) extensionSpec(name string) (extension.Spec, bool) {
	if name == "" || server.extensions == nil {
		return extension.Spec{}, false
	}
	for _, spec := range server.extensions.specs {
		if spec.Name == name {
			return spec, true
		}
	}
	return extension.Spec{}, false
}
