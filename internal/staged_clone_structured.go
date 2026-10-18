// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"unicode/utf8"
)

// Common decoded JSON containers need no reflection. Preserve the original
// concrete scalar/container types, depth bounds, nils and UTF-8 validation;
// uncommon typed containers still use the existing reflective implementation.
func cloneStagedStructured(value interface{}, depth, limit int) (interface{}, bool, error) {
	switch typed := value.(type) {
	case map[string]interface{}:
		copy, err := cloneStagedObject(typed, depth, limit)
		return copy, true, err
	case []interface{}:
		copy, err := cloneStagedArray(typed, depth, limit)
		return copy, true, err
	case string:
		if !utf8.ValidString(typed) {
			return nil, true, fmt.Errorf("owned text is not valid UTF-8")
		}
		return typed, true, nil
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return value, true, nil
	default:
		return nil, false, nil
	}
}

func cloneStagedObject(value map[string]interface{}, depth, limit int) (map[string]interface{}, error) {
	if value == nil {
		return nil, nil
	}
	copy := make(map[string]interface{}, len(value))
	for key, child := range value {
		if !utf8.ValidString(key) {
			return nil, fmt.Errorf("owned map key is not valid UTF-8")
		}
		cloned, err := cloneStagedValue(child, depth+1, limit)
		if err != nil {
			return nil, err
		}
		copy[key] = cloned
	}
	return copy, nil
}

func cloneStagedArray(value []interface{}, depth, limit int) ([]interface{}, error) {
	if value == nil {
		return nil, nil
	}
	copy := make([]interface{}, len(value))
	for index, child := range value {
		cloned, err := cloneStagedValue(child, depth+1, limit)
		if err != nil {
			return nil, err
		}
		copy[index] = cloned
	}
	return copy, nil
}
