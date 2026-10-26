// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"encoding/json"
	"fmt"
)

func deriveCarriers(request Request, all []Record) (Request, int, error) {
	var result map[string]interface{}
	if len(request.Result) > 0 && string(request.Result) != "null" {
		if err := json.Unmarshal(request.Result, &result); err != nil {
			return request, 0, err
		}
	}
	if result["derive_carrier_events"] != true {
		return request, 0, nil
	}
	count := 0
	for _, presence := range append([]Mutation(nil), request.Mutations...) {
		if presence.Family != "business:presence_event" || presence.NativeID != "" {
			continue
		}
		if !carrierTrigger(presence.Data["event_type"]) {
			continue
		}
		for _, asset := range carrierAssets(all, presence.Data["employee_id"]) {
			request.Mutations = append(request.Mutations, carrierMutation(presence, asset))
			request.References = append(request.References, Reference{Family: asset.Family, Key: asset.Key, NativeID: asset.NativeID, Version: asset.Version, Fields: []string{"type", "assigned_to_employee_id"}})
			count++
		}
	}
	result["derived_asset_event_count"] = count
	request.Result, _ = json.Marshal(result)
	return request, count, nil
}
func carrierTrigger(value interface{}) bool {
	return value == "arrived" || value == "clocked_in" || value == "dispatched"
}
func carrierAssets(all []Record, employee interface{}) []Record {
	result := []Record{}
	for _, record := range all {
		if record.Family == "business:asset" && validCarrierType(record.Data["type"]) && same(record.Data["assigned_to_employee_id"], employee) && employee != nil {
			result = append(result, record)
		}
	}
	return result
}
func validCarrierType(value interface{}) bool {
	return value == "tool" || value == "vehicle" || value == "material"
}
func carrierMutation(presence Mutation, asset Record) Mutation {
	eventType := "moved_to_employee"
	if presence.Data["location_id"] != nil {
		eventType = "moved_to_location"
	}
	if presence.Data["job_id"] != nil {
		eventType = "moved_to_job"
	}
	id := hash([]string{presence.Key, asset.Key, "carrier_moved"})[:32]
	id = fmt.Sprintf("%s-%s-%s-%s-%s", id[:8], id[8:12], id[12:16], id[16:20], id[20:])
	data := map[string]interface{}{"id": id, "account_id": presence.Data["account_id"], "entity_type": asset.Data["type"], "entity_id": asset.Key, "event_type": eventType, "cause": "carrier_moved", "caused_by_event_id": presence.Key, "notes": "Derived from carrier presence event"}
	for _, key := range []string{"job_id", "employee_id", "location_id", "occurred_at"} {
		data[key] = presence.Data[key]
	}
	return Mutation{Family: "business:asset_event", Key: id, Data: data}
}
