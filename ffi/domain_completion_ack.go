// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package main

/*
#include "lumberjack.h"
*/
import "C"

import "github.com/NeoTecDigital/LumberJack/embedded"

//export ic_lj_domain_ack_completion
func ic_lj_domain_ack_completion(req C.lj_cstr, n C.int64_t, out **C.char, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	if n <= 0 || n > 8192 {
		return statusInvalid
	}
	body, bad := take(req, n)
	if bad != statusOK {
		return bad
	}
	result, err := embedded.DomainAcknowledgeCompletionCall(body)
	return domainOutput(result, err, out, outLen)
}
