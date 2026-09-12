// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The wire codec: YAML on the boundary, the HTTP surface's JSON names on the document.
//
// The view and request structs carry `json:` tags only. Rather than tag sixteen of them a second
// time — where a `yaml:` tag could quietly disagree with its `json:` tag and fork the two surfaces —
// every document is routed THROUGH JSON. The field names are therefore provably the HTTP names, in
// one place. The cost is a caution the header states: on decode, the YAML parser resolves a bare
// scalar in a `map[string]interface{}` (metadata) into an int, a nil or a timestamp before it is a
// string. Typed fields never see this; metadata does, so identity-bearing metadata must be quoted.
package main

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/NeoTecDigital/LumberJack/embedded"
	"gopkg.in/yaml.v3"
)

// encodeYAML renders a Go value as a YAML document whose keys are its json names.
//
// Go value -> JSON (json tags) -> generic tree -> YAML. The JSON hop carries the json field names;
// its numbers are decoded with UseNumber so a plain json.Unmarshal does not first widen every one to
// float64 and lose every integer past 2^53 — epoch, oldest and sequence are all UnixNano-scale and
// live there. withNumbers then turns each json.Number into an integer the YAML emitter writes as a
// number rather than a quoted string, so it round-trips back through decodeYAML exactly.
func encodeYAML(value interface{}) ([]byte, error) {
	asJSON, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(asJSON))
	decoder.UseNumber()
	var generic interface{}
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	return yaml.Marshal(withNumbers(generic))
}

// withNumbers converts every json.Number in a decoded tree into the narrowest numeric Go type that
// holds it, so the YAML emitter renders it as a number. A json.Number is a string underneath, which
// yaml would otherwise quote — and a quoted integer does not decode back into a uint64 field. This
// fixes epoch, oldest and sequence uniformly rather than special-casing any one of them.
func withNumbers(node interface{}) interface{} {
	switch value := node.(type) {
	case json.Number:
		if i, err := value.Int64(); err == nil {
			return i
		}
		if u, err := strconv.ParseUint(value.String(), 10, 64); err == nil {
			return u
		}
		if f, err := value.Float64(); err == nil {
			return f
		}
		return value.String()
	case map[string]interface{}:
		for key, child := range value {
			value[key] = withNumbers(child)
		}
		return value
	case []interface{}:
		for i, child := range value {
			value[i] = withNumbers(child)
		}
		return value
	default:
		return node
	}
}

// decodeYAML parses a YAML document into a Go value by its json names.
//
// YAML -> generic tree -> JSON -> Go value (json tags). The generic hop is where the metadata
// coercion the header warns of happens; typed destination fields are unaffected because JSON carries
// the value into a typed field, not a bare interface{}.
func decodeYAML(document []byte, into interface{}) error {
	var generic interface{}
	if err := yaml.Unmarshal(document, &generic); err != nil {
		return err
	}

	asJSON, err := json.Marshal(generic)
	if err != nil {
		return err
	}
	return json.Unmarshal(asJSON, into)
}

// openRequest is the YAML body of ic_lj_open: enough config to name a state file, and the principal
// the handle acts as.
type openRequest struct {
	Organization string `json:"organization"`
	DatabasePath string `json:"database_path"`
	Name         string `json:"name"`
	Principal    string `json:"principal"`
}

// adoptRequest is the YAML body of ic_lj_adopt: only what names a state file. No organization and no
// principal, because adoption opens nothing and acts as nobody.
type adoptRequest struct {
	DatabasePath string `json:"database_path"`
	Name         string `json:"name"`
}

// pollRequest is the YAML body of ic_lj_stream_poll.
type pollRequest struct {
	After     uint64 `json:"after"`
	Epoch     uint64 `json:"epoch"`
	TimeoutMS int64  `json:"timeout_ms"`
}

// pollResponse is its answer. On a gap the events are dropped — they are not a coherent continuation
// — and `oldest` is the sequence the caller re-derives from.
type pollResponse struct {
	Events   []embedded.MutationEvent `json:"events"`
	Epoch    uint64                   `json:"epoch"`
	CaughtUp bool                     `json:"caught_up"`
	Oldest   uint64                   `json:"oldest"`
}
