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

func domainOutput(body []byte, err error, out **C.char, outLen *C.int64_t) C.lj_status_t {
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	if err != nil {
		body = embedded.DomainFailure("domain_denied")
	}
	allocated := C.CBytes(body)
	if allocated == nil {
		return statusInternal
	}
	*out = (*C.char)(allocated)
	*outLen = C.int64_t(len(body))
	return statusOK
}
func domainHandleInput(h C.lj_handle_t, req C.lj_cstr, n C.int64_t) (*embedded.Handle, []byte, C.lj_status_t) {
	handle, ok := lookupHandle(uint64(h))
	if !ok {
		return nil, nil, statusBadHandle
	}
	body, status := take(req, n)
	return handle, body, status
}

//export ic_lj_domain_configure
func ic_lj_domain_configure(h C.lj_handle_t, req C.lj_cstr, n C.int64_t, out **C.char, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	handle, body, bad := domainHandleInput(h, req, n)
	if bad != statusOK {
		return bad
	}
	result, err := handle.ConfigureDomain(body)
	return domainOutput(result, err, out, outLen)
}

//export ic_lj_domain_resolve
func ic_lj_domain_resolve(h C.lj_handle_t, req C.lj_cstr, n C.int64_t, out **C.char, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	handle, body, bad := domainHandleInput(h, req, n)
	if bad != statusOK {
		return bad
	}
	result, err := handle.DomainResolve(body)
	return domainOutput(result, err, out, outLen)
}

//export ic_lj_domain_call
func ic_lj_domain_call(h C.lj_handle_t, req C.lj_cstr, n C.int64_t, out **C.char, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	handle, body, bad := domainHandleInput(h, req, n)
	if bad != statusOK {
		return bad
	}
	result, err := handle.DomainCall(body)
	return domainOutput(result, err, out, outLen)
}

//export ic_lj_domain_control
func ic_lj_domain_control(req C.lj_cstr, n C.int64_t, out **C.char, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	body, bad := take(req, n)
	if bad != statusOK {
		return bad
	}
	result, err := embedded.DomainControlCall(body)
	return domainOutput(result, err, out, outLen)
}

//export ic_lj_domain_free
func ic_lj_domain_free(out *C.char) { C.free(unsafe.Pointer(out)) }
