// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package abi

/*
#include "lumberjack.h"
*/
import "C"
import (
	"errors"
	"sync"
	"unsafe"

	"github.com/NeoTecDigital/LumberJack/embedded"
	"github.com/NeoTecDigital/LumberJack/internal/store"
)

var records sync.Map // uint64 -> *embedded.RecordHandle; numbers share the base token allocator.
func recordStatus(e error) C.lj_status_t {
	switch {
	case e == nil:
		return statusOK
	case errors.Is(e, store.ErrInvalid):
		return statusInvalid
	case errors.Is(e, store.ErrDenied):
		return statusForbidden
	case errors.Is(e, store.ErrConflict):
		return statusConflict
	case errors.Is(e, store.ErrAbsent):
		return statusNotFound
	case errors.Is(e, store.ErrUnavailable):
		return statusBusy
	default:
		return openStatus(e)
	}
}
func RecordOpen(req unsafe.Pointer, n int64, out unsafe.Pointer) int32 {
	return int32(recordOpen(C.lj_cstr(req), C.int64_t(n), (*C.lj_handle_t)(out), false))
}
func RecordOpenV2(req unsafe.Pointer, n int64, out unsafe.Pointer) int32 {
	return int32(recordOpen(C.lj_cstr(req), C.int64_t(n), (*C.lj_handle_t)(out), true))
}
func recordOpen(req C.lj_cstr, n C.int64_t, out *C.lj_handle_t, v2 bool) (st C.lj_status_t) {
	defer guard(&st, nil)
	if out == nil {
		return statusInvalid
	}
	*out = 0
	if len(registered()) != 0 {
		return statusConflict
	}
	if n > store.MaxBytes {
		return statusTooLarge
	}
	raw, bad := take(req, n)
	if bad != statusOK {
		return bad
	}
	type baseConfig struct {
		Directory  string `json:"directory"`
		Name       string `json:"name"`
		Principal  string `json:"principal"`
		Durability string `json:"durability"`
	}
	var r struct {
		baseConfig
		Indexes  []embedded.RecordIndex `json:"indexes,omitempty"`
		ReadOnly bool                   `json:"read_only,omitempty"`
	}
	var target any = &r.baseConfig
	if v2 {
		target = &r
	}
	if err := store.Decode(raw, target); err != nil || r.Durability != "local-sync" {
		return statusInvalid
	}
	h, e := embedded.OpenIndexedRecords(r.Directory, r.Name, r.Principal, r.Indexes, r.ReadOnly)
	if e != nil {
		return recordStatus(e)
	}
	id := handleIdx.Add(1)
	records.Store(id, h)
	*out = C.lj_handle_t(id)
	return statusOK
}
func RecordClose(h uint64) int32 { return int32(recordClose(h)) }
func recordClose(h uint64) (st C.lj_status_t) {
	defer guard(&st, nil)
	v, ok := records.LoadAndDelete(h)
	if !ok {
		return statusOK
	}
	return recordStatus(v.(*embedded.RecordHandle).Close())
}
func RecordData(apply bool, h uint64, req unsafe.Pointer, n int64, out unsafe.Pointer, cap int64, length unsafe.Pointer) int32 {
	return int32(recordData(apply, false, h, C.lj_cstr(req), C.int64_t(n), (*C.char)(out), C.int64_t(cap), (*C.int64_t)(length)))
}
func RecordIndexedPage(h uint64, req unsafe.Pointer, n int64, out unsafe.Pointer, cap int64, length unsafe.Pointer) int32 {
	return int32(recordData(false, true, h, C.lj_cstr(req), C.int64_t(n), (*C.char)(out), C.int64_t(cap), (*C.int64_t)(length)))
}
func recordData(write, indexed bool, id uint64, req C.lj_cstr, n C.int64_t, out *C.char, cap C.int64_t, length *C.int64_t) (st C.lj_status_t) {
	defer guard(&st, length)
	if length == nil || out == nil || cap < 0 {
		return statusInvalid
	}
	*length = 0
	if n > store.MaxBytes {
		return statusTooLarge
	}
	h, ok := records.Load(id)
	if !ok {
		return statusBadHandle
	}
	b, st := take(req, n)
	if st != statusOK {
		return st
	}
	rh := h.(*embedded.RecordHandle)
	var err error
	if write {
		b, err = rh.Apply(b)
	} else if indexed {
		b, err = rh.IndexedPage(b)
	} else {
		b, err = rh.Page(b)
	}
	if err != nil {
		return recordStatus(err)
	}
	return answer(b, out, cap, length)
}
