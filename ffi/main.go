// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// Command lumberjack-ffi is the C ABI: Lumberjack's embedded API, serialised.
//
// It is `package main` because -buildmode=c-archive requires one, and it lives in its own
// directory because the module root already has a main. `func main` is never called — the
// archive's entry points are the //export'd functions, and the Go runtime is brought up
// from .init_array before the host's main.
//
// ffi/lumberjack.h is the specification, and this file INCLUDES it rather than restating
// it. The signatures cgo generates are therefore built from the specification's own types,
// so the two agree by construction and ctest/header_agreement.c is checking that they still
// do rather than hoping.
package main

/*
#cgo CFLAGS: -I${SRCDIR}
#include "lumberjack.h"
*/
import "C"

import (
	"fmt"
	"os"
	"runtime/debug"
	"unsafe"
)

// abiVersion is the number ffi/lumberjack.h declares. The header is the specification, so
// this follows it; header_agreement.c is what proves they still agree.
const abiVersion = 1

// Statuses, mirroring ffi/lumberjack.h. Only the ones this stub can produce are named.
const (
	statusOK        = 0
	statusInvalid   = 1
	statusTruncated = 8
	statusPanic     = 11
)

func main() {}

//export ic_lj_abi_version
func ic_lj_abi_version() C.uint32_t {
	return C.uint32_t(abiVersion)
}

//export ic_lj_echo
func ic_lj_echo(in C.lj_cstr, inLen C.int32_t,
	out *C.char, outCap C.int32_t, outLen *C.int32_t) (status C.lj_status_t) {

	defer guard(&status, outLen)

	body, bad := take(in, inLen)
	if bad != statusOK {
		return C.lj_status_t(bad)
	}
	return C.lj_status_t(answer(body, out, outCap, outLen))
}

// take copies an input buffer into Go memory.
//
// A COPY, not a view: cgo's rules let C free its buffer the moment the call returns, and a
// Go value pointing into it would be a use-after-free the race detector cannot see.
func take(ptr C.lj_cstr, length C.int32_t) ([]byte, int) {
	if length < 0 {
		return nil, statusInvalid
	}
	if length == 0 {
		return nil, statusOK
	}
	if ptr == nil {
		return nil, statusInvalid
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length)), statusOK
}

// answer writes a document into the caller's buffer, or reports what it would have needed.
//
// `*out_len` is set in BOTH cases, because the size is the one thing a caller that got
// LJ_TRUNCATED needs in order to try again. Nothing is written when it does not fit: a
// caller cannot tell a partial document from a whole one, so a partial one is a lie.
func answer(document []byte, out *C.char, outCap C.int32_t, outLen *C.int32_t) int {
	if outLen == nil {
		return statusInvalid
	}
	*outLen = C.int32_t(len(document))

	if outCap < 0 || (len(document) > 0 && out == nil) {
		return statusInvalid
	}
	if C.int32_t(len(document)) > outCap {
		return statusTruncated
	}
	if len(document) > 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outCap)), document)
	}
	return statusOK
}

// guard turns a panic into a status instead of a dead process.
//
// It must be the FIRST statement of every export, and the result must be NAMED: recover is
// only legal inside a deferred function, and a deferred function can only change the result
// if there is a name to assign to.
//
// Its honest limit, which belongs beside it rather than in a design document: recover
// catches a PANIC. It does not catch a runtime throw — a concurrent map write, an
// out-of-memory — and internal/forest_lock.go:17 names that case exactly. What keeps this
// process alive under concurrency is the forest lock. This is containment for a bug in one
// handler, and it is not a licence to relax that lock.
func guard(status *C.lj_status_t, outLen *C.int32_t) {
	recovered := recover()
	if recovered == nil {
		return
	}
	*status = C.lj_status_t(statusPanic)
	if outLen != nil {
		*outLen = 0
	}
	fmt.Fprintf(os.Stderr, "lumberjack ffi: recovered panic: %v\n%s", recovered, debug.Stack())
}
