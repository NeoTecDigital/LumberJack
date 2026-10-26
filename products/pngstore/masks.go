// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"sort"
	"strings"
)

func requiredDataFields(request Request, selected []Record, nativeID, operation, rootID string, defaults map[string][]string) []string {
	fields := map[string]bool{}
	if operation == "png.store.read" {
		readFields(fields, request.Query, selected, nativeID)
		queryFields(fields, request.Query)
	} else {
		writeFields(fields, request, selected, nativeID, rootID)
		addDefaultIntentFields(fields, request, selected, nativeID, rootID, defaults)
	}
	result := []string{}
	for key := range fields {
		result = append(result, "data."+key)
	}
	sort.Strings(result)
	return result
}
func queryFields(fields map[string]bool, query Query) {
	for _, filter := range query.Filters {
		addFields(fields, strings.FieldsFunc(filter.Field, func(char rune) bool { return char == '|' || char == ',' }))
	}
	for _, field := range query.OrderBy {
		fields[strings.TrimPrefix(field, "-")] = true
	}
}
func readFields(fields map[string]bool, query Query, selected []Record, nativeID string) {
	for _, record := range selected {
		if record.NativeID != nativeID {
			continue
		}
		if len(query.Fields) > 0 {
			addFields(fields, query.Fields)
			return
		}
		for key := range record.Data {
			fields[key] = true
		}
	}
}
func addFields(fields map[string]bool, keys []string) {
	for _, key := range keys {
		fields[key] = true
	}
}
func writeFields(fields map[string]bool, request Request, selected []Record, nativeID, rootID string) {
	for _, mutation := range request.Mutations {
		if mutation.NativeID != nativeID && !(nativeID == rootID && mutation.NativeID == "") {
			continue
		}
		fields["account_id"] = true
		fields["id"] = true
		for key := range mutation.Data {
			fields[key] = true
		}
	}
	for _, unique := range request.Unique {
		if nativeID == rootID || familyForID(selected, nativeID) == unique.Family {
			addDataKeys(fields, unique.Fields)
		}
	}
	for _, reference := range request.References {
		if reference.NativeID == nativeID {
			addFields(fields, reference.Fields)
		}
		if reference.NativeID == nativeID && reference.Subtype != nil {
			fields["type"] = true
		}
	}
}
func familyForID(selected []Record, id string) string {
	for _, record := range selected {
		if record.NativeID == id {
			return record.Family
		}
	}
	return ""
}
func addDataKeys(fields map[string]bool, data map[string]interface{}) {
	for key := range data {
		fields[key] = true
	}
}
func maskRecords(records []Record, fields []string) []Record {
	if len(fields) == 0 {
		return records
	}
	for index, record := range records {
		records[index].Data = maskedData(record.Data, fields)
	}
	return records
}
func maskedData(data map[string]interface{}, fields []string) map[string]interface{} {
	result := map[string]interface{}{}
	for _, key := range fields {
		if value, present := data[key]; present {
			result[key] = value
		}
	}
	return result
}
