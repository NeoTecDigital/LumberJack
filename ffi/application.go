package main

/*
#include <stdlib.h>
#include "lumberjack.h"
*/
import "C"

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/embedded"
	"unsafe"
)

//export ic_lj_application_configure
func ic_lj_application_configure(h C.lj_handle_t, req C.lj_cstr, n C.int64_t) (status C.lj_status_t) {
	defer guard(&status, nil)
	handle, ok := lookupHandle(uint64(h))
	if !ok {
		return statusBadHandle
	}
	body, bad := take(req, n)
	if bad != statusOK {
		return bad
	}
	var config struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Secret   string `json:"secret"`
	}
	if json.Unmarshal(body, &config) != nil {
		return statusCodec
	}
	if err := handle.ConfigureApplication(config.Username, config.Password, config.Secret); err != nil {
		return statusInvalid
	}
	return statusOK
}

//export ic_lj_application_call
func ic_lj_application_call(h C.lj_handle_t, req C.lj_cstr, n C.int64_t, out **C.char, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if out == nil || outLen == nil {
		return statusInvalid
	}
	*out = nil
	*outLen = 0
	handle, ok := lookupHandle(uint64(h))
	if !ok {
		return statusBadHandle
	}
	body, bad := take(req, n)
	if bad != statusOK {
		return bad
	}
	var request embedded.ApplicationRequest
	var envelope struct {
		Hub json.RawMessage `json:"hub"`
	}
	if json.Unmarshal(body, &envelope) == nil && len(envelope.Hub) > 0 {
		encoded, err := handle.ApplicationHub(envelope.Hub)
		if err != nil {
			return statusForError(err)
		}
		*out = (*C.char)(C.CBytes(encoded))
		*outLen = C.int64_t(len(encoded))
		return statusOK
	}
	if json.Unmarshal(body, &request) != nil {
		return statusCodec
	}
	response, err := handle.ApplicationCall(request)
	if err != nil {
		return statusForError(err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return statusCodec
	}
	// An owned result is never replayed just because the caller's output buffer
	// was too small. Mutations execute exactly once per call across this boundary.
	*out = (*C.char)(C.CBytes(encoded))
	*outLen = C.int64_t(len(encoded))
	return statusOK
}

//export ic_lj_application_free
func ic_lj_application_free(out *C.char) { C.free(unsafe.Pointer(out)) }
