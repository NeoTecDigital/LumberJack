// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"unicode/utf8"
)

func DecodeDomainJSON(data []byte, target interface{}) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid UTF-8")
	}
	if err := domainJSONEscapes(data); err != nil {
		return err
	}
	if err := checkDomainJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(interface{})) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

type domainJSONFrame struct {
	object bool
	key    bool
	seen   map[string]bool
}

func checkDomainJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	stack := []domainJSONFrame{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		stack, err = domainJSONToken(stack, token)
		if err != nil {
			return err
		}
	}
}
func domainJSONToken(stack []domainJSONFrame, token json.Token) ([]domainJSONFrame, error) {
	if delim, ok := token.(json.Delim); ok {
		return domainJSONDelimiter(stack, delim)
	}
	if len(stack) == 0 {
		return stack, nil
	}
	return stack, domainJSONScalar(&stack[len(stack)-1], token)
}
func domainJSONDelimiter(stack []domainJSONFrame, delim json.Delim) ([]domainJSONFrame, error) {
	if delim == '{' || delim == '[' {
		return append(stack, domainJSONFrame{object: delim == '{', key: true, seen: map[string]bool{}}), nil
	}
	if len(stack) == 0 {
		return nil, fmt.Errorf("invalid JSON delimiter")
	}
	stack = stack[:len(stack)-1]
	if len(stack) > 0 {
		stack[len(stack)-1].key = true
	}
	return stack, nil
}
func domainJSONScalar(frame *domainJSONFrame, token interface{}) error {
	if !frame.object {
		return nil
	}
	if !frame.key {
		frame.key = true
		return nil
	}
	key, ok := token.(string)
	if !ok || frame.seen[key] {
		return fmt.Errorf("duplicate/invalid JSON key")
	}
	frame.seen[key] = true
	frame.key = false
	return nil
}

func domainJSONEscapes(data []byte) error {
	for index := 0; index < len(data); index++ {
		if data[index] != '\\' {
			continue
		}
		index++
		if index >= len(data) || data[index] != 'u' {
			continue
		}
		if index+4 >= len(data) {
			return fmt.Errorf("invalid Unicode escape")
		}
		value, err := strconv.ParseUint(string(data[index+1:index+5]), 16, 16)
		if err != nil {
			return err
		}
		index += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return fmt.Errorf("unpaired low surrogate")
		}
		if value < 0xd800 || value > 0xdbff {
			continue
		}
		if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
			return fmt.Errorf("unpaired high surrogate")
		}
		low, err := strconv.ParseUint(string(data[index+3:index+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return fmt.Errorf("unpaired high surrogate")
		}
		index += 6
	}
	return nil
}
func CanonicalDomainJSON(value interface{}) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var decoded interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	return canonicalDomainValue(decoded)
}
func canonicalDomainValue(value interface{}) ([]byte, error) {
	switch value := value.(type) {
	case string:
		return canonicalDomainString(value)
	case map[string]interface{}:
		return canonicalDomainObject(value)
	case []interface{}:
		return canonicalDomainArray(value)
	case json.Number:
		// Product envelopes contain text only; arbitrary numeric spellings are not authority.
		return []byte(value.String()), nil
	default:
		return json.Marshal(value)
	}
}
func canonicalDomainString(value string) ([]byte, error) {
	if !utf8.ValidString(value) {
		return nil, fmt.Errorf("invalid Unicode")
	}
	var out bytes.Buffer
	out.WriteByte('"')
	for _, r := range value {
		out.WriteString(canonicalDomainRune(r))
	}
	out.WriteByte('"')
	return out.Bytes(), nil
}
func canonicalDomainRune(r rune) string {
	switch r {
	case '"':
		return "\\\""
	case '\\':
		return "\\\\"
	case '\b':
		return "\\b"
	case '\f':
		return "\\f"
	case '\n':
		return "\\n"
	case '\r':
		return "\\r"
	case '\t':
		return "\\t"
	}
	if r < 32 {
		return fmt.Sprintf("\\u%04x", r)
	}
	return string(r)
}
func canonicalDomainObject(value map[string]interface{}) ([]byte, error) {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out bytes.Buffer
	out.WriteByte('{')
	for index, key := range keys {
		if index > 0 {
			out.WriteByte(',')
		}
		encoded, err := canonicalDomainValue(value[key])
		if err != nil {
			return nil, err
		}
		name, err := canonicalDomainString(key)
		if err != nil {
			return nil, err
		}
		out.Write(name)
		out.WriteByte(':')
		out.Write(encoded)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}
func canonicalDomainArray(value []interface{}) ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('[')
	for index, element := range value {
		if index > 0 {
			out.WriteByte(',')
		}
		encoded, err := canonicalDomainValue(element)
		if err != nil {
			return nil, err
		}
		out.Write(encoded)
	}
	out.WriteByte(']')
	return out.Bytes(), nil
}
func domainEqual(a, b interface{}) bool {
	first, err := CanonicalDomainJSON(a)
	if err != nil {
		return false
	}
	second, err := CanonicalDomainJSON(b)
	return err == nil && bytes.Equal(first, second)
}
func domainValidHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := strconv.ParseUint(value[:16], 16, 64)
	if err != nil {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
