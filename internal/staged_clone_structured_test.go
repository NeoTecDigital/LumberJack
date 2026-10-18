// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
)

func TestStagedStructuredClonePreservesConcreteTypesExactNumbersAndNils(t *testing.T) {
	var object map[string]interface{}
	var array []interface{}
	value := map[string]interface{}{"number": json.Number("9007199254740993"), "integer": int64(9007199254740993),
		"small": int8(12), "unsigned": uint64(18446744073709551615), "float": float32(0.25),
		"typed": []string{"original"}, "map": map[string]string{"key": "original"},
		"nested": []interface{}{map[string]interface{}{"exact": " original "}}, "nil": nil, "object": object, "array": array}
	copy, err := cloneStagedMetadata(value, stagedTestBounds())
	if err != nil || !reflect.DeepEqual(value, copy) {
		t.Fatal("structured clone changed types, nulls or numeric precision", err)
	}
	copy["nested"].([]interface{})[0].(map[string]interface{})["exact"] = "changed"
	copy["typed"].([]string)[0] = "changed"
	copy["map"].(map[string]string)["key"] = "changed"
	if value["typed"].([]string)[0] != "original" || value["map"].(map[string]string)["key"] != "original" || value["nested"].([]interface{})[0].(map[string]interface{})["exact"] != " original " {
		t.Fatal("structured clone retained a mutable alias")
	}
}

func TestStagedStructuredCloneStillRejectsInvalidOwnedValues(t *testing.T) {
	for _, value := range []interface{}{string([]byte{0xff}), map[string]interface{}{string([]byte{0xff}): "bad"},
		json.RawMessage(`{"raw":true}`), math.NaN(), math.Inf(1), make(chan int), new(string),
		map[int]string{1: "unsupported"}, json.Number("not-a-number")} {
		if _, err := cloneStagedMetadata(map[string]interface{}{"value": value}, stagedTestBounds()); err == nil {
			t.Fatalf("invalid owned value accepted: %T", value)
		}
	}
}

func TestStagedStructuredCloneKeepsDepthAndCycleBounds(t *testing.T) {
	value := map[string]interface{}{"nested": []interface{}{map[string]interface{}{"value": "too deep"}}}
	if _, err := cloneStagedValue(value, 0, 2); err == nil {
		t.Fatal("structured clone bypassed depth bound")
	}
	cycle := map[string]interface{}{}
	cycle["self"] = cycle
	if _, err := cloneStagedValue(cycle, 0, 3); err == nil {
		t.Fatal("structured clone accepted a cycle")
	}
}
