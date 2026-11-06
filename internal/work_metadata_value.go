package internal

import "encoding/json"

// Metadata is JSON-shaped at mutation time, just as after reload. This keeps
// rollback snapshots byte-stable for the durable acknowledgement hash.
func workMetadataValue(value interface{}) interface{} {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var result interface{}
	if json.Unmarshal(raw, &result) != nil {
		return nil
	}
	return result
}
