package abi

/*
#include "lumberjack.h"
*/
import "C"

import "github.com/NeoTecDigital/LumberJack/embedded"

func baseEventsPublish(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	if reqLen > C.int64_t(C.LJ_PUBLISH_MAX_BYTES) {
		return statusTooLarge
	}
	return runOp(h, req, reqLen, out, outCap, outLen, mutation, opEventsPublish)
}

func opEventsPublish(h *embedded.Handle, body []byte) (interface{}, C.lj_status_t) {
	if len(body) > embedded.PublishMaxBytes {
		return nil, statusTooLarge
	}
	var request embedded.PublishEventsRequest
	if err := decodeYAML(body, &request); err != nil {
		return nil, statusCodec
	}
	result, err := h.PublishEvents(request)
	if err != nil {
		return nil, statusForError(err)
	}
	return result, statusOK
}
