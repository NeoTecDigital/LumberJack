// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// Command lumberjack-ffi is the C ABI: Lumberjack's embedded API, serialised.
//
// It is `package main` because -buildmode=c-archive requires one, and it lives in its own
// directory because the module root already has a main. `func main` is never called — the
// archive's entry points are the //export'd functions, and the Go runtime is brought up
// from .init_array before the host's main.
//
// It imports `embedded` ONLY, never `internal`: the ABI is a serialisation of the embedded
// Go API, so the two cannot drift. ffi/lumberjack.h is the specification, and this package
// INCLUDES it rather than restating it, so the signatures cgo generates are built from the
// specification's own types and ctest/header_agreement.c checks that they still agree.
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
const abiVersion = C.LJ_ABI_VERSION

// The statuses, sourced from the header's own macros so there is one numbering, not two. A
// conversion of a #define'd constant to the C typedef is a constant expression, so these are
// real Go constants and the header stays the single source header_agreement.c holds to account.
const (
	statusOK        = C.lj_status_t(C.LJ_OK)
	statusInvalid   = C.lj_status_t(C.LJ_INVALID)
	statusForbidden = C.lj_status_t(C.LJ_FORBIDDEN)
	statusNotFound  = C.lj_status_t(C.LJ_NOT_FOUND)
	statusConflict  = C.lj_status_t(C.LJ_CONFLICT)
	statusTooLarge  = C.lj_status_t(C.LJ_TOO_LARGE)
	statusInternal  = C.lj_status_t(C.LJ_INTERNAL)
	statusTruncated = C.lj_status_t(C.LJ_TRUNCATED)
	statusBadHandle = C.lj_status_t(C.LJ_BAD_HANDLE)
	statusClosed    = C.lj_status_t(C.LJ_CLOSED)
	statusPanic     = C.lj_status_t(C.LJ_PANIC)
	statusCodec     = C.lj_status_t(C.LJ_CODEC)
	statusGap       = C.lj_status_t(C.LJ_GAP)
	statusLocked    = C.lj_status_t(C.LJ_LOCKED)
	statusBusy      = C.lj_status_t(C.LJ_BUSY)
)

func main() {}

//export ic_lj_abi_version
func ic_lj_abi_version() C.uint32_t {
	return C.uint32_t(abiVersion)
}

//export ic_lj_echo
func ic_lj_echo(in C.lj_cstr, inLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {

	defer guard(&status, outLen)

	body, bad := take(in, inLen)
	if bad != statusOK {
		return bad
	}
	return answer(body, out, outCap, outLen)
}

// maxTakeLen bounds the Go allocation a single inbound copy may demand. in_len is int64 as of ABI
// v2, so a caller could otherwise ask take to allocate up to 8 EiB — or, more practically, force a
// multi-gigabyte allocation per call. It is the header's LJ_MAX_IN_LEN, so the number the binding
// enforces is the one the specification declares. A request past it is refused LJ_TOO_LARGE before a
// byte is copied.
const maxTakeLen = C.LJ_MAX_IN_LEN

// take copies an input buffer into Go memory.
//
// A COPY, not a view: cgo's rules let C free its buffer the moment the call returns, and a
// Go value pointing into it would be a use-after-free the race detector cannot see.
//
// unsafe.Slice, not C.GoBytes: C.GoBytes takes a C.int, which is 32 bits, so it would truncate a
// length past 2 GiB — the very width this ABI widened in_len to reach. The Slice views the C buffer
// and the make+copy is the copy out of it; the buffer is never retained past the return.
func take(ptr C.lj_cstr, length C.int64_t) ([]byte, C.lj_status_t) {
	if length < 0 {
		return nil, statusInvalid
	}
	if length > maxTakeLen {
		return nil, statusTooLarge
	}
	if length == 0 {
		return nil, statusOK
	}
	if ptr == nil {
		return nil, statusInvalid
	}
	buf := make([]byte, length)
	copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(length)))
	return buf, statusOK
}

// answer writes a document into the caller's buffer, or reports what it would have needed.
//
// `*out_len` is set in BOTH cases, because the size is the one thing a caller that got
// LJ_TRUNCATED needs in order to try again. Nothing is written when it does not fit: a
// caller cannot tell a partial document from a whole one, so a partial one is a lie.
func answer(document []byte, out *C.char, outCap C.int64_t, outLen *C.int64_t) C.lj_status_t {
	if outLen == nil {
		return statusInvalid
	}
	report, fitStatus := answerPlan(int64(len(document)), int64(outCap))
	*outLen = C.int64_t(report)

	if outCap < 0 || (len(document) > 0 && out == nil) {
		return statusInvalid
	}
	if fitStatus == statusTruncated {
		return statusTruncated
	}
	if len(document) > 0 {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outCap)), document)
	}
	return statusOK
}

// answerPlan is answer's arithmetic with none of its memory: given the document size and the buffer
// capacity, the length to report in *out_len and whether the document fit. Both are int64 — that IS
// the ABI-v2 fix. When *out_len was int32, a document of 2^31 bytes reported a NEGATIVE length, and
// because a negative compares below out_cap the call returned LJ_OK for a document that did not fit
// and was copied only in part. Extracted so that exact boundary is testable without allocating a
// multi-gigabyte document: answerPlan(1<<31, small) must report 1<<31 and answer LJ_TRUNCATED.
func answerPlan(docLen, outCap int64) (report int64, status C.lj_status_t) {
	if docLen > outCap {
		return docLen, statusTruncated
	}
	return docLen, statusOK
}

// guard turns a panic into a status instead of a dead process.
//
// It must be the FIRST statement of every export, and the result must be NAMED: recover is
// only legal inside a deferred function, and a deferred function can only change the result
// if there is a name to assign to.
//
// Its honest limit, which belongs beside it rather than in a design document: recover
// catches a PANIC. It does not catch a runtime throw — a concurrent map write, an
// out-of-memory — and internal/forest_lock.go names that case exactly. What keeps this
// process alive under concurrency is the forest lock. This is containment for a bug in one
// handler, and it is not a licence to relax that lock.
func guard(status *C.lj_status_t, outLen *C.int64_t) {
	recovered := recover()
	if recovered == nil {
		return
	}
	*status = statusPanic
	if outLen != nil {
		*outLen = 0
	}
	fmt.Fprintf(os.Stderr, "lumberjack ffi: recovered panic: %v\n%s", recovered, debug.Stack())
}
