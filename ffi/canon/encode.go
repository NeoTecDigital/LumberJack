// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

package canon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"sort"

	"golang.org/x/text/unicode/norm"
)

// Encode returns canonical(v): the bytes §11.2 defines, or a refusal. It never resolves what
// the specification refuses — a duplicate is an error, a node past MaxDepth is an error.
func Encode(v Value) ([]byte, error) {
	return encodeAt(v, 0)
}

func encodeAt(v Value, depth int) ([]byte, error) {
	var e encoder
	if err := e.value(v, depth); err != nil {
		return nil, err
	}
	return e.buf.Bytes(), nil
}

type encoder struct{ buf bytes.Buffer }

// value emits one node. Depth is tested on the node itself before its shape is looked at, so a
// scalar at 65 and a list at 65 are refused alike, and an empty list at 64 is accepted.
func (e *encoder) value(v Value, depth int) error {
	if depth > MaxDepth {
		return refuse(NestingTooDeep, "a node at depth %d is deeper than %d", depth, MaxDepth)
	}
	switch v := v.(type) {
	case List:
		return e.list(v, depth+1)
	case Map:
		return e.mapping(v, depth+1)
	case Record:
		return e.record(v, depth+1)
	case Ref:
		// The one unframed value: the tag and the 32-byte id. A length here would be a constant.
		e.buf.WriteByte(byte(TagRef))
		e.buf.Write(v[:])
		return nil
	default:
		return e.scalar(v)
	}
}

// scalar is the byte-length rule: every scalar is tag, u32 length, body. Byte order is
// declared little-endian and integers are two's complement of their stated width.
func (e *encoder) scalar(v Value) error {
	var body []byte
	switch v := v.(type) {
	case Null:
	case Bool:
		body = []byte{boolByte(bool(v))}
	case Int:
		body = binary.LittleEndian.AppendUint64(nil, uint64(v))
	case Decimal:
		body = v.body()
	case String:
		body = []byte(nfc(string(v)))
	case Timestamp:
		body = binary.LittleEndian.AppendUint64(nil, uint64(v))
	case Date:
		body = binary.LittleEndian.AppendUint32(nil, uint32(v))
	case Duration:
		body = binary.LittleEndian.AppendUint64(nil, uint64(v))
	case UUID:
		body = v[:]
	default:
		return fmt.Errorf("canon: %T is not a value", v)
	}
	return e.frame(v.canonTag(), body)
}

func (e *encoder) frame(tag Tag, body []byte) error {
	if err := e.header(tag, len(body)); err != nil {
		return err
	}
	e.buf.Write(body)
	return nil
}

// header opens a value: the tag, then the u32 little-endian prefix — a byte length for a
// scalar, an item count for a collection.
func (e *encoder) header(tag Tag, n int) error {
	if n < 0 || uint64(n) > math.MaxUint32 {
		return fmt.Errorf("canon: %d does not fit the u32 prefix", n)
	}
	e.buf.WriteByte(byte(tag))
	e.buf.Write(binary.LittleEndian.AppendUint32(nil, uint32(n)))
	return nil
}

// list is the count rule over elements in written order.
func (e *encoder) list(l List, depth int) error {
	if err := e.header(TagList, len(l)); err != nil {
		return err
	}
	for _, item := range l {
		if err := e.value(item, depth); err != nil {
			return err
		}
	}
	return nil
}

type encodedEntry struct{ key, value []byte }

// mapping encodes every entry first, then orders them by canonical key bytes. Canonical forms
// are prefix-free, so bytewise order needs no tiebreak; two equal keys have no order at all
// and are refused.
func (e *encoder) mapping(m Map, depth int) error {
	entries := make([]encodedEntry, len(m))
	for i, entry := range m {
		key, err := encodeAt(entry.Key, depth)
		if err != nil {
			return err
		}
		value, err := encodeAt(entry.Value, depth)
		if err != nil {
			return err
		}
		entries[i] = encodedEntry{key: key, value: value}
	}
	sort.SliceStable(entries, func(i, j int) bool { return bytes.Compare(entries[i].key, entries[j].key) < 0 })
	for i := 1; i < len(entries); i++ {
		if bytes.Equal(entries[i-1].key, entries[i].key) {
			return refuse(DuplicateMapKey, "two entries share the key %x", entries[i].key)
		}
	}
	if err := e.header(TagMap, len(entries)); err != nil {
		return err
	}
	for _, entry := range entries {
		e.buf.Write(entry.key)
		e.buf.Write(entry.value)
	}
	return nil
}

type namedField struct {
	name   string // NFC
	value  Value
	absent bool
}

// record counts present fields only, but every declaration — present or absent — takes part in
// the duplicate check: an absent field is still a declaration of its name.
func (e *encoder) record(r Record, depth int) error {
	fields, err := sortedFields(r)
	if err != nil {
		return err
	}
	present := 0
	for _, f := range fields {
		if !f.absent {
			present++
		}
	}
	if err := e.header(TagRecord, present); err != nil {
		return err
	}
	for _, f := range fields {
		if f.absent {
			continue
		}
		if err := e.frame(TagString, []byte(f.name)); err != nil {
			return err
		}
		if err := e.value(f.value, depth); err != nil {
			return err
		}
	}
	return nil
}

// sortedFields normalises every name to NFC before sorting, so that two NFC-equal names are
// adjacent and refused, and then orders by raw UTF-8 bytes: a shorter name before any it
// prefixes, and never by anything per-build.
func sortedFields(r Record) ([]namedField, error) {
	fields := make([]namedField, len(r))
	for i, f := range r {
		fields[i] = namedField{name: nfc(f.Name), value: f.Value, absent: f.Absent}
	}
	sort.SliceStable(fields, func(i, j int) bool { return fields[i].name < fields[j].name })
	for i := 1; i < len(fields); i++ {
		if fields[i-1].name == fields[i].name {
			return nil, refuse(DuplicateField, "the field %q is declared twice", fields[i].name)
		}
	}
	return fields, nil
}

// nfc is the string rule's normalisation: the full Unicode NFC, not a table of the characters
// a corpus happens to use.
func nfc(s string) string { return norm.NFC.String(s) }
