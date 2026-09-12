// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

package canon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
)

// Corpus is the §11.4 conformance corpus, decoded and built into values.
type Corpus struct {
	Note     []string
	MaxDepth int
	Cases    []Case
	Pairs    []Pair
}

// Case is one corpus case with its value built. Expect is accepted, refused or id_only; Kind
// is present when the case derives an id; SelfRef names a field whose ref is the case's own id.
type Case struct {
	Name         string
	Note         string
	Expect       string
	Value        Value
	Kind         *Kind
	CanonicalHex string
	IDHex        string
	Error        string
	SelfRef      string
}

// Pair is two cases the corpus compares by canonical bytes or by id.
type Pair struct {
	A       string `json:"a"`
	B       string `json:"b"`
	Compare string `json:"compare"`
	Expect  string `json:"expect"`
	Rule    string `json:"rule"`
}

// ByName indexes the cases. Two cases under one name would make a pair ambiguous, so that is
// an error rather than a last-wins.
func (c *Corpus) ByName() (map[string]Case, error) {
	byName := make(map[string]Case, len(c.Cases))
	for _, cs := range c.Cases {
		if _, dup := byName[cs.Name]; dup {
			return nil, fmt.Errorf("canon: corpus names the case %q twice", cs.Name)
		}
		byName[cs.Name] = cs
	}
	return byName, nil
}

// The wire shapes. Every struct is decoded with unknown keys refused: a reader that ignores
// what it does not understand is exactly the failure the corpus exists to catch.
type corpusJSON struct {
	Note     []string   `json:"note"`
	MaxDepth int        `json:"max_depth"`
	Cases    []caseJSON `json:"cases"`
	Pairs    []Pair     `json:"pairs"`
}

type caseJSON struct {
	Name         string    `json:"name"`
	Note         string    `json:"note"`
	Value        rawValue  `json:"value"`
	Expect       string    `json:"expect"`
	CanonicalHex string    `json:"canonical_hex"`
	IDHex        string    `json:"id_hex"`
	Error        string    `json:"error"`
	Kind         *kindJSON `json:"kind"`
	SelfRef      string    `json:"self_ref"`
}

type kindJSON struct {
	FQN    string   `json:"fqn"`
	IDFrom []string `json:"id_from"`
}

// rawValue is the corpus value grammar: a tag and a tag-shaped payload. Nothing here passes
// through float64 — every number the corpus carries is a string, and a JSON number where a
// string is expected is an error, not a conversion.
type rawValue struct {
	T     string          `json:"t"`
	V     json.RawMessage `json:"v"`
	Depth int             `json:"depth"`
}

type rawField struct {
	Name   string    `json:"name"`
	Value  *rawValue `json:"value"`
	Absent bool      `json:"absent"`
}

// Load reads a corpus file and builds every case's value.
func Load(path string) (*Corpus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wire corpusJSON
	if err := strictUnmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("canon: corpus %s: %w", path, err)
	}
	corpus := &Corpus{Note: wire.Note, MaxDepth: wire.MaxDepth, Pairs: wire.Pairs}
	for _, c := range wire.Cases {
		built, err := c.build()
		if err != nil {
			return nil, fmt.Errorf("canon: corpus case %q: %w", c.Name, err)
		}
		corpus.Cases = append(corpus.Cases, built)
	}
	return corpus, nil
}

func strictUnmarshal(data []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data after the value")
	}
	return nil
}

func (c caseJSON) build() (Case, error) {
	value, err := c.Value.build()
	if err != nil {
		return Case{}, err
	}
	built := Case{
		Name: c.Name, Note: c.Note, Expect: c.Expect, Value: value,
		CanonicalHex: c.CanonicalHex, IDHex: c.IDHex, Error: c.Error, SelfRef: c.SelfRef,
	}
	if c.Kind != nil {
		built.Kind = &Kind{FQN: c.Kind.FQN, IDFrom: c.Kind.IDFrom}
	}
	return built, nil
}

func (r rawValue) build() (Value, error) {
	if r.T != "nest" && r.Depth != 0 {
		return nil, fmt.Errorf("%s carries a depth; only nest does", r.T)
	}
	switch r.T {
	case "list":
		return r.list()
	case "map":
		return r.mapping()
	case "record":
		return r.record()
	case "nest":
		return r.nest()
	}
	return r.scalar()
}

func (r rawValue) scalar() (Value, error) {
	switch r.T {
	case "null":
		return r.null()
	case "bool":
		return r.boolean()
	case "int":
		return r.integer(func(n int64) Value { return Int(n) })
	case "timestamp":
		return r.integer(func(n int64) Value { return Timestamp(n) })
	case "duration":
		return r.integer(func(n int64) Value { return Duration(n) })
	case "date":
		return r.date()
	case "decimal":
		return r.decimal()
	case "str":
		return r.str()
	case "uuid":
		return r.uuid()
	case "ref":
		return r.ref()
	}
	return nil, fmt.Errorf("unknown value tag %q", r.T)
}

func (r rawValue) null() (Value, error) {
	if r.V != nil {
		return nil, fmt.Errorf("null carries no v")
	}
	return Null{}, nil
}

func (r rawValue) boolean() (Value, error) {
	var b bool
	if err := strictUnmarshal(r.V, &b); err != nil {
		return nil, fmt.Errorf("bool: v must be a JSON bool: %w", err)
	}
	return Bool(b), nil
}

// text is the carrier for every numeric and textual scalar: a JSON string, decoded as one.
func (r rawValue) text() (string, error) {
	var s string
	if err := strictUnmarshal(r.V, &s); err != nil {
		return "", fmt.Errorf("%s: v must be a JSON string (numbers are carried as strings): %w", r.T, err)
	}
	return s, nil
}

func (r rawValue) integer(wrap func(int64) Value) (Value, error) {
	s, err := r.text()
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%s: %q is not an i64", r.T, s)
	}
	return wrap(n), nil
}

func (r rawValue) date() (Value, error) {
	s, err := r.text()
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("date: %q is not an i32", s)
	}
	return Date(int32(n)), nil
}

func (r rawValue) decimal() (Value, error) {
	s, err := r.text()
	if err != nil {
		return nil, err
	}
	return ParseDecimal(s)
}

func (r rawValue) str() (Value, error) {
	s, err := r.text()
	if err != nil {
		return nil, err
	}
	return String(s), nil
}

func (r rawValue) hexBytes(width int) ([]byte, error) {
	s, err := r.text()
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %q is not hex", r.T, s)
	}
	if len(b) != width {
		return nil, fmt.Errorf("%s: %d bytes, want %d", r.T, len(b), width)
	}
	return b, nil
}

func (r rawValue) uuid() (Value, error) {
	b, err := r.hexBytes(16)
	if err != nil {
		return nil, err
	}
	return UUID(b), nil
}

func (r rawValue) ref() (Value, error) {
	b, err := r.hexBytes(IDSize)
	if err != nil {
		return nil, err
	}
	return Ref(b), nil
}

func (r rawValue) list() (Value, error) {
	var items []rawValue
	if err := strictUnmarshal(r.V, &items); err != nil {
		return nil, fmt.Errorf("list: v must be an array of values: %w", err)
	}
	out := make(List, 0, len(items))
	for _, item := range items {
		v, err := item.build()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r rawValue) mapping() (Value, error) {
	var entries [][]rawValue
	if err := strictUnmarshal(r.V, &entries); err != nil {
		return nil, fmt.Errorf("map: v must be an array of [key, value]: %w", err)
	}
	out := make(Map, 0, len(entries))
	for i, entry := range entries {
		if len(entry) != 2 {
			return nil, fmt.Errorf("map: entry %d has %d parts, want [key, value]", i, len(entry))
		}
		key, err := entry[0].build()
		if err != nil {
			return nil, err
		}
		value, err := entry[1].build()
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{Key: key, Value: value})
	}
	return out, nil
}

func (r rawValue) record() (Value, error) {
	var fields []rawField
	if err := strictUnmarshal(r.V, &fields); err != nil {
		return nil, fmt.Errorf("record: v must be an array of fields: %w", err)
	}
	out := make(Record, 0, len(fields))
	for _, f := range fields {
		field, err := f.build()
		if err != nil {
			return nil, err
		}
		out = append(out, field)
	}
	return out, nil
}

func (f rawField) build() (Field, error) {
	if f.Absent {
		if f.Value != nil {
			return Field{}, fmt.Errorf("field %q is absent and carries a value", f.Name)
		}
		return Field{Name: f.Name, Absent: true}, nil
	}
	if f.Value == nil {
		return Field{}, fmt.Errorf("field %q is neither present nor absent", f.Name)
	}
	v, err := f.Value.build()
	if err != nil {
		return Field{}, err
	}
	return Field{Name: f.Name, Value: v}, nil
}

// nest is the corpus shorthand for v wrapped in depth single-element lists; it is expanded
// here so what is hashed is the lists themselves.
func (r rawValue) nest() (Value, error) {
	if r.Depth < 0 {
		return nil, fmt.Errorf("nest: depth %d is negative", r.Depth)
	}
	var inner rawValue
	if err := strictUnmarshal(r.V, &inner); err != nil {
		return nil, fmt.Errorf("nest: v must be a value: %w", err)
	}
	v, err := inner.build()
	if err != nil {
		return nil, err
	}
	for i := 0; i < r.Depth; i++ {
		v = List{v}
	}
	return v, nil
}
