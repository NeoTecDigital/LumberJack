// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package main

/*
#include <stdlib.h>
#include "lumberjack.h"
*/
import "C"

import (
	"github.com/NeoTecDigital/LumberJack/embedded"
	"unsafe"
)

func personalSourceOutput(body []byte, err error, out **C.char, outLen *C.int64_t) C.lj_status_t {
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	if err != nil {
		body = embedded.PersonalSourceFailure(err)
	}
	allocated := C.CBytes(body)
	if allocated == nil {
		return statusInternal
	}
	*out = (*C.char)(allocated)
	*outLen = C.int64_t(len(body))
	return statusOK
}

//export ic_lj_personal_source_configure
func ic_lj_personal_source_configure(h C.lj_handle_t, req C.lj_cstr, n C.int64_t, out **C.char, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	handle, raw, bad := domainHandleInput(h, req, n)
	if bad != statusOK {
		return bad
	}
	result, err := handle.ConfigurePersonalSource(raw)
	return personalSourceOutput(result, err, out, outLen)
}

//export ic_lj_personal_source_call
func ic_lj_personal_source_call(h C.lj_handle_t, req C.lj_cstr, n C.int64_t, out **C.char, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	handle, raw, bad := domainHandleInput(h, req, n)
	if bad != statusOK {
		return bad
	}
	result, err := handle.PersonalSourceCall(raw)
	return personalSourceOutput(result, err, out, outLen)
}

//export ic_lj_personal_source_control
func ic_lj_personal_source_control(req C.lj_cstr, n C.int64_t, out **C.char, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	raw, bad := take(req, n)
	if bad != statusOK {
		return bad
	}
	result, err := embedded.PersonalSourceControlCall(raw)
	return personalSourceOutput(result, err, out, outLen)
}

//export ic_lj_personal_source_free
func ic_lj_personal_source_free(out *C.char) { C.free(unsafe.Pointer(out)) }

//export ic_lj_native_control_configure
func ic_lj_native_control_configure(h C.lj_handle_t, req C.lj_cstr, n C.int64_t, out **C.char, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	handle, raw, bad := domainHandleInput(h, req, n)
	if bad != statusOK {
		return bad
	}
	result, err := handle.ConfigureNativeControl(raw)
	return personalSourceOutput(result, err, out, outLen)
}

//export ic_lj_native_source_verify_seal
func ic_lj_native_source_verify_seal(req C.lj_cstr, n C.int64_t, out **C.char, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	raw, bad := take(req, n)
	if bad != statusOK {
		return bad
	}
	result, err := embedded.VerifyNativeSourceSeal(raw)
	return personalSourceOutput(result, err, out, outLen)
}
