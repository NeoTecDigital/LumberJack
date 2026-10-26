// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"fmt"
	"strings"
)

func baseStoreFields(ceiling []string) []string {
	fields := []string{}
	for _, field := range ceiling {
		if !strings.HasPrefix(field, "data.") && !strings.HasPrefix(field, "family.") && field != "reference" {
			fields = append(fields, field)
		}
	}
	return fields
}
func checkStoreCeiling(fields, ceiling []string) error {
	permitted := map[string]bool{}
	for _, field := range ceiling {
		permitted[field] = true
	}
	for _, field := range fields {
		if !permitted[field] {
			return fmt.Errorf("actual native field exceeds explicit owner ceiling: %s", field)
		}
	}
	return nil
}
