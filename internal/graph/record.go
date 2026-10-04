// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// parseRecord reads a put value. It must be a JSON object; numbers stay raw so that integer
// geometry and revisions are never widened to float64 on the way through.
func parseRecord(raw json.RawMessage) (Record, error) {
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&record); err != nil {
		return nil, err
	}
	if record == nil {
		return nil, errors.New("must be an object")
	}
	return record, nil
}

func recordString(record Record, key string) string {
	if record == nil {
		return ""
	}
	var value string
	_ = json.Unmarshal(record[key], &value)
	return value
}

func recordUint(record Record, key string) uint64 {
	if record == nil {
		return 0
	}
	var number json.Number
	if err := json.Unmarshal(record[key], &number); err != nil {
		return 0
	}
	value, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func setString(record Record, key, value string) {
	encoded, _ := json.Marshal(value)
	record[key] = encoded
}

func setUint(record Record, key string, value uint64) {
	record[key] = json.RawMessage(strconv.FormatUint(value, 10))
}

// cloneRecord copies the map. The raw values are never written in place, so sharing them is safe.
func cloneRecord(record Record) Record {
	if record == nil {
		return nil
	}
	out := make(Record, len(record))
	for key, value := range record {
		out[key] = value
	}
	return out
}

// recordText is a record as the JSON text it is stored under. Keys are sorted by encoding/json, so
// one record has one text.
func recordText(value interface{}) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

// safeID is a caller-chosen handle: a command id, a view id or an alias.
func safeID(id string) bool {
	return id != "" && len(id) <= 256 && !strings.ContainsAny(id, "\x00\r\n")
}

// semanticID is an entity, occurrence or edge id: exactly 64 LOWERCASE hex digits. hex.DecodeString
// would accept upper case, and an id that two spellings reach is two ids.
func semanticID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// commandDigest covers the payload AS THE CALLER SENT IT, so reusing an id with a changed
// fingerprint, actor or operation set cannot replay a different command's result. It is taken
// before the actor is defaulted: a retry that left the actor out again must match the first
// attempt whoever the session belongs to, and one that now names an actor is a different command.
func commandDigest(cmd Command) string {
	payload := map[string]interface{}{
		"fingerprint": cmd.Fingerprint,
		"actor":       cmd.Actor,
		"expected":    cmd.Expected,
		"operations":  cmd.Operations,
	}
	sum := sha256.Sum256(canonicalJSON(payload))
	return hex.EncodeToString(sum[:])
}

// canonicalJSON is value as JSON with every object's keys sorted, at every depth.
func canonicalJSON(value interface{}) []byte {
	encoded, _ := json.Marshal(value)
	var generic interface{}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	_ = decoder.Decode(&generic)
	var out bytes.Buffer
	writeCanonical(&out, generic)
	return out.Bytes()
}

func writeCanonical(out *bytes.Buffer, value interface{}) {
	switch typed := value.(type) {
	case map[string]interface{}:
		writeCanonicalObject(out, typed)
	case []interface{}:
		out.WriteByte('[')
		for i, element := range typed {
			if i > 0 {
				out.WriteByte(',')
			}
			writeCanonical(out, element)
		}
		out.WriteByte(']')
	default:
		encoded, _ := json.Marshal(typed)
		out.Write(encoded)
	}
}

func writeCanonicalObject(out *bytes.Buffer, object map[string]interface{}) {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		encodedKey, _ := json.Marshal(key)
		out.Write(encodedKey)
		out.WriteByte(':')
		writeCanonical(out, object[key])
	}
	out.WriteByte('}')
}
