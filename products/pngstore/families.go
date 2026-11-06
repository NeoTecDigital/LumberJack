// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import "sort"

// Families are explicit native ACL scope fields, not permissions inferred from data.
func requiredFamilyFields(request Request, selected []Record, id, rootID string) []string {
	families := map[string]bool{}
	if id == rootID {
		rootFamilies(families, request)
	} else {
		families[familyForID(selected, id)] = true
	}
	result := []string{}
	for family := range families {
		if family != "" {
			result = append(result, "family."+family)
		}
	}
	sort.Strings(result)
	return result
}
func rootFamilies(families map[string]bool, request Request) {
	if request.Query.Family != "" {
		families[request.Query.Family] = true
	}
	for _, mutation := range request.Mutations {
		families[mutation.Family] = true
	}
	for _, reference := range request.References {
		families[reference.Family] = true
	}
	for _, unique := range request.Unique {
		families[unique.Family] = true
	}
}
