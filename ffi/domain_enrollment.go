// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package main

/*
#include "lumberjack.h"
*/
import "C"

//export ic_lj_domain_enroll
func ic_lj_domain_enroll(handle C.lj_handle_t, request C.lj_cstr, length C.int64_t, output **C.char, outputLength *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outputLength)
	if output == nil || outputLength == nil {
		return statusInvalid
	}
	*output, *outputLength = nil, 0
	owner, body, invalid := domainHandleInput(handle, request, length)
	if invalid != statusOK {
		return invalid
	}
	result, err := owner.DomainEnrollJSON(body)
	return domainOutput(result, err, output, outputLength)
}
