// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package pngstore

import (
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"strings"
	"time"
)

func validateCreateDefaults(defaults map[string][]string) error {
	for family, fields := range defaults {
		if !strings.HasPrefix(family, "business:") || family == "business:" || len(fields) != 1 || fields[0] != "created_at" {
			return fmt.Errorf("owner defaults require exact application business family and created_at rule")
		}
	}
	return nil
}
func defaultKeys(request Request, mutation Mutation, defaults map[string][]string) []string {
	if mutation.NativeID != "" || mutation.Patch || strings.HasPrefix(request.Action, "migration.") {
		return nil
	}
	return defaults[mutation.Family]
}
func applicationDefaults(request Request, owned engine.DomainOwnedScope) (Request, error) {
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	for index, mutation := range request.Mutations {
		if err := mutationDefaults(&mutation, defaultKeys(request, mutation, owned.Layout.ApplicationCreateDefaults), stamp); err != nil {
			return request, err
		}
		request.Mutations[index] = mutation
	}
	return request, nil
}
func mutationDefaults(mutation *Mutation, keys []string, stamp string) error {
	for _, key := range keys {
		if err := defaultValue(mutation, key, stamp); err != nil {
			return err
		}
	}
	return nil
}
func defaultValue(mutation *Mutation, key, stamp string) error {
	if value, present := mutation.Data[key]; present {
		if value == nil {
			return fmt.Errorf("explicit null denied by owner application create rule")
		}
		return nil
	}
	if mutation.Data == nil {
		return fmt.Errorf("explicit creation data required")
	}
	mutation.Data[key] = stamp
	return nil
}
func addDefaultIntentFields(fields map[string]bool, request Request, selected []Record, id, rootID string, defaults map[string][]string) {
	for _, mutation := range request.Mutations {
		if id == rootID && mutation.NativeID == "" || mutation.NativeID == id {
			addFields(fields, defaultKeys(request, mutation, defaults))
		}
	}
}
func addDefaultTargetFields(fields map[string]bool, request Request, mutation Mutation, defaults map[string][]string) {
	for _, key := range defaultKeys(request, mutation, defaults) {
		fields["data."+key] = true
	}
}
