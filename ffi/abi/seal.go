// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package abi

/*
#include "lumberjack.h"
*/
import "C"
import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/types"
	"path/filepath"
	"unsafe"

	"github.com/NeoTecDigital/LumberJack/embedded"
	"github.com/NeoTecDigital/LumberJack/internal/store"
)

func RecordSeal(req unsafe.Pointer, n int64, out unsafe.Pointer) int32 {
	return int32(seal(C.lj_cstr(req), C.int64_t(n), (*C.uint8_t)(out)))
}
func seal(req C.lj_cstr, n C.int64_t, out *C.uint8_t) (st C.lj_status_t) {
	defer guard(&st, nil)
	if out == nil {
		return statusInvalid
	}
	*out = 0
	if n > embedded.MaxRecordRequestBytes {
		return statusTooLarge
	}
	raw, st := take(req, n)
	if st != statusOK {
		return st
	}
	var r embedded.SealRequest
	if e := store.Decode(raw, &r); e != nil {
		return statusInvalid
	}
	already, e := embedded.SealAccount(r)
	if e == nil && already {
		*out = 1
	}
	return recordStatus(e)
}

func RecordMarker(req unsafe.Pointer, n int64, out unsafe.Pointer, cap int64, length unsafe.Pointer) int32 {
	return int32(marker(C.lj_cstr(req), C.int64_t(n), (*C.char)(out), C.int64_t(cap), (*C.int64_t)(length)))
}
func marker(req C.lj_cstr, n C.int64_t, out *C.char, cap C.int64_t, length *C.int64_t) (st C.lj_status_t) {
	defer guard(&st, length)
	if out == nil || length == nil || cap < 0 {
		return statusInvalid
	}
	*length = 0
	if n > embedded.MaxRecordRequestBytes {
		return statusTooLarge
	}
	b, st := take(req, n)
	if st != statusOK {
		return st
	}
	var q struct {
		Path    string               `json:"path"`
		Storage *types.StorageConfig `json:"storage"`
	}
	if e := store.Decode(b, &q); e != nil || !filepath.IsAbs(q.Path) {
		return statusInvalid
	}
	cfg, e := types.ResolveOpenStorage(q.Storage)
	if e != nil {
		return statusSealingLabel
	}
	if cfg != nil && (cfg.MigrateLegacy || cfg.RewrapKeys) {
		return statusInvalid
	}
	name, e := store.MarkerOwner(q.Path, cfg)
	if e != nil {
		return recordStatus(e)
	}
	raw, e := json.Marshal(name)
	if e != nil {
		return statusInvalid
	}
	return answer(raw, out, cap, length)
}
