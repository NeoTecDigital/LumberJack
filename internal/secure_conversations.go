// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// The encrypted conversations section, read for compatibility (docs/extension-api.md §7.5, owner
// decision Q4(a)). A store sealed before the split wrote each conversation's header and each of its
// messages as a resource of its own. They are opened with the backend key and reassembled, as
// bytes and in Order, into the root's "conversations" slot — the same object the store's plaintext
// form holds — so nothing about them needs a type here. On the next write the slot is sealed inside
// the root, and the section is not written again.

// openConversations reassembles the section into the conversations object.
func (s *secureStorage) openConversations(master []byte, sections map[string]encryptedConversation) (json.RawMessage, error) {
	conversations := make(map[string]json.RawMessage, len(sections))
	for id, saved := range sections {
		header, err := s.openResource(master, "conversation/"+id, saved.Header)
		if err != nil {
			return nil, err
		}
		if !hasIdentity(header, id) {
			return nil, errors.New("encrypted conversation identity mismatch")
		}
		messages, err := s.openMessages(master, id, saved)
		if err != nil {
			return nil, err
		}
		if messages != nil {
			if header, err = replaceTopLevelValue(header, "messages", messages); err != nil {
				return nil, err
			}
		}
		conversations[id] = header
	}
	return json.Marshal(conversations)
}

// openMessages is a conversation's messages, in Order, as one JSON array; nil when it has none.
func (s *secureStorage) openMessages(master []byte, id string, saved encryptedConversation) (json.RawMessage, error) {
	if len(saved.Order) == 0 {
		return nil, nil
	}
	var array bytes.Buffer
	array.WriteByte('[')
	for index, messageID := range saved.Order {
		body, err := s.openResource(master, "message/"+id+"/"+messageID, saved.Messages[messageID])
		if err != nil {
			return nil, err
		}
		if !hasIdentity(body, messageID) {
			return nil, errors.New("encrypted message identity mismatch")
		}
		if index > 0 {
			array.WriteByte(',')
		}
		if err := json.Compact(&array, body); err != nil {
			return nil, err
		}
	}
	array.WriteByte(']')
	return array.Bytes(), nil
}

// hasIdentity reports whether a sealed body names the id it was sealed under.
func hasIdentity(body []byte, id string) bool {
	var named struct {
		ID string `json:"id"`
	}
	return json.Unmarshal(body, &named) == nil && named.ID == id
}

// replaceTopLevelValue answers a JSON object with one top-level key's value replaced, every other
// key and value kept as the bytes it was, in its place.
func replaceTopLevelValue(object []byte, key string, value json.RawMessage) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(object))
	if open, err := decoder.Token(); err != nil || open != json.Delim('{') {
		return nil, fmt.Errorf("a conversation header is not a JSON object")
	}
	var out bytes.Buffer
	out.WriteByte('{')
	replaced := false
	for first := true; decoder.More(); first = false {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, _ := token.(string)
		var held json.RawMessage
		if err := decoder.Decode(&held); err != nil {
			return nil, err
		}
		if name == key {
			held, replaced = value, true
		}
		if !first {
			out.WriteByte(',')
		}
		encodedName, _ := json.Marshal(name)
		out.Write(encodedName)
		out.WriteByte(':')
		out.Write(held)
	}
	if !replaced {
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		encodedName, _ := json.Marshal(key)
		out.Write(encodedName)
		out.WriteByte(':')
		out.Write(value)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}
