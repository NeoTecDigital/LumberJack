// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/internal"
)

// hubExtensions preserves attachment order and excludes declarations that
// apply only to the record profile. Unknown scopes are never opted out.
func hubExtensions(exts []extension.Extension) ([]extension.Extension, error) {
	var hub []extension.Extension
	for _, ext := range exts {
		if ext == nil {
			return nil, internal.ErrExtensionSet
		}
		switch ext.Spec().Scope {
		case extension.AllStores, extension.HubStore:
			hub = append(hub, ext)
		case extension.RecordStore:
			continue
		default:
			return nil, internal.ErrExtensionSet
		}
	}
	return hub, nil
}

// CheckRecordExtensions admits only explicitly hub-only registrations. Both
// v1 and v2 journals have no extension dispatch, including on reader opens.
func CheckRecordExtensions(exts []extension.Extension) error {
	for _, ext := range exts {
		if ext == nil || ext.Spec().Scope != extension.HubStore {
			return ErrRecordConflict
		}
	}
	return nil
}
