// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The twelve exports. Each is `defer guard` then a thin translation to an embedded call: look up the
// handle, copy the request, run, encode the answer. The engine's behaviour, its holds and its
// persist all live below embedded; nothing here decides anything the HTTP surface does not.
package main

/*
#include "lumberjack.h"
*/
import "C"

import (
	"errors"
	"time"

	"github.com/NeoTecDigital/LumberJack/embedded"
)

//export ic_lj_open
func ic_lj_open(req C.lj_cstr, reqLen C.int64_t, outHandle *C.lj_handle_t) (status C.lj_status_t) {
	defer guard(&status, nil)

	if outHandle == nil {
		return statusInvalid
	}

	body, bad := take(req, reqLen)
	if bad != statusOK {
		return bad
	}

	var r openRequest
	if err := decodeYAML(body, &r); err != nil {
		return statusCodec
	}

	handle, err := embedded.OpenPath(r.Organization, r.DatabasePath, r.Name, r.Principal)
	if err != nil {
		if errors.Is(err, embedded.ErrLocked) {
			return statusLocked
		}
		return statusInternal
	}

	*outHandle = C.lj_handle_t(registerHandle(handle))
	return statusOK
}

//export ic_lj_close
func ic_lj_close(h C.lj_handle_t) (status C.lj_status_t) {
	defer guard(&status, nil)

	// A miss is LJ_OK, not an error: closing twice, or closing a token that never opened, is benign.
	// The strictness is on the DATA calls, which answer LJ_BAD_HANDLE to a miss.
	handle, ok := dropHandle(uint64(h))
	if !ok {
		return statusOK
	}
	if err := handle.Close(); err != nil {
		return statusInternal
	}
	return statusOK
}

//export ic_lj_node_create
func ic_lj_node_create(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	return runOp(h, req, reqLen, out, outCap, outLen, mutation, opNodeCreate)
}

//export ic_lj_event_plan
func ic_lj_event_plan(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	return runOp(h, req, reqLen, out, outCap, outLen, mutation, opEventPlan)
}

//export ic_lj_event_start
func ic_lj_event_start(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	return runOp(h, req, reqLen, out, outCap, outLen, mutation, opEventStart)
}

//export ic_lj_event_append
func ic_lj_event_append(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	return runOp(h, req, reqLen, out, outCap, outLen, mutation, opEventAppend)
}

//export ic_lj_event_end
func ic_lj_event_end(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	return runOp(h, req, reqLen, out, outCap, outLen, mutation, opEventEnd)
}

//export ic_lj_event_entries
func ic_lj_event_entries(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	return runOp(h, req, reqLen, out, outCap, outLen, read, opEventEntries)
}

//export ic_lj_query
func ic_lj_query(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	return runOp(h, req, reqLen, out, outCap, outLen, read, opQuery)
}

//export ic_lj_aggregate
func ic_lj_aggregate(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	return runOp(h, req, reqLen, out, outCap, outLen, read, opAggregate)
}

//export ic_lj_forest
func ic_lj_forest(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)
	return runOp(h, req, reqLen, out, outCap, outLen, read, opForest)
}

//export ic_lj_stream_poll
func ic_lj_stream_poll(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t) (status C.lj_status_t) {
	defer guard(&status, outLen)

	handle, ok := lookupHandle(uint64(h))
	if !ok {
		return statusBadHandle
	}

	body, bad := take(req, reqLen)
	if bad != statusOK {
		return bad
	}

	var r pollRequest
	if err := decodeYAML(body, &r); err != nil {
		return statusCodec
	}

	timeout, bad := pollTimeout(r.TimeoutMS)
	if bad != statusOK {
		return bad
	}
	batch := handle.PollMutations(r.After, timeout)

	// A cursor from another run is as stale as one off the back of the ring: sequences restart on
	// every open, so an epoch that is not this run's is a gap of its own.
	gap := !batch.CaughtUp || (r.Epoch != 0 && r.Epoch != batch.Epoch)

	resp := pollResponse{Epoch: batch.Epoch, Oldest: batch.Oldest, CaughtUp: !gap}
	if !gap {
		resp.Events = batch.Events
	}

	doc, err := encodeYAML(resp)
	if err != nil {
		return statusCodec
	}
	if written := answer(doc, out, outCap, outLen); written != statusOK {
		return written
	}
	if gap {
		return statusGap
	}
	return statusOK
}

// maxPollTimeoutMS caps how long a single poll may block. Two failures live in an unbounded
// timeout_ms. Past ~9.2e12 ms the `time.Duration(ms) * time.Millisecond` multiply overflows int64
// into a NEGATIVE duration, and a negative timer fires at once — so the largest requests became the
// shortest waits. And even in range, an uncapped timeout pins the calling OS thread for as long as
// asked, with no exit but a Close from another thread. Five minutes is far longer than any healthy
// poll waits; a caller wanting to wait longer polls again.
const maxPollTimeoutMS = 5 * 60 * 1000

// pollTimeout turns a wire timeout_ms into a bounded duration. A negative value is nonsense and is
// refused; anything past the cap is clamped to it, keeping the millisecond multiply in int64 range
// and the thread's hold bounded.
func pollTimeout(ms int64) (time.Duration, C.lj_status_t) {
	if ms < 0 {
		return 0, statusInvalid
	}
	if ms > maxPollTimeoutMS {
		ms = maxPollTimeoutMS
	}
	return time.Duration(ms) * time.Millisecond, statusOK
}

// mutation and read name the two kinds of operation, so a call site reads as what it is rather than
// as a bare bool.
const (
	mutation = true
	read     = false
)

// runOp is the body every data export shares: resolve the handle, copy the request, refuse a
// mutation whose acknowledgement could not fit BEFORE it runs, then run, encode and write.
func runOp(h C.lj_handle_t, req C.lj_cstr, reqLen C.int64_t,
	out *C.char, outCap C.int64_t, outLen *C.int64_t,
	isMutation bool, op func(*embedded.Handle, []byte) (interface{}, C.lj_status_t)) C.lj_status_t {

	handle, ok := lookupHandle(uint64(h))
	if !ok {
		return statusBadHandle
	}

	body, bad := take(req, reqLen)
	if bad != statusOK {
		return bad
	}

	// The acknowledgement guard, BEFORE the mutation runs: a write that happened and could not be
	// acknowledged is a write the caller does not know it made. answer can fail three ways — no
	// out_len to report the size, no out buffer to hold a document that is always non-empty for a
	// mutation, or a buffer below the floor its bounded fields need — and ALL THREE are knowable here,
	// before op(). A mutation whose acknowledgement cannot be delivered does not run.
	if isMutation && (outLen == nil || out == nil || outCap < C.int64_t(C.LJ_MUTATION_OUT_MIN)) {
		return statusInvalid
	}

	value, status := op(handle, body)
	if status != statusOK {
		return status
	}

	doc, err := encodeYAML(value)
	if err != nil {
		return statusCodec
	}
	return answer(doc, out, outCap, outLen)
}

func opNodeCreate(h *embedded.Handle, body []byte) (interface{}, C.lj_status_t) {
	var r embedded.CreateNodeRequest
	if err := decodeYAML(body, &r); err != nil {
		return nil, statusCodec
	}
	if s := boundedFields(r.Path, ""); s != statusOK {
		return nil, s
	}
	answer, err := h.CreateNode(r)
	if err != nil {
		return nil, statusForError(err)
	}
	return answer, statusOK
}

func opEventPlan(h *embedded.Handle, body []byte) (interface{}, C.lj_status_t) {
	var r embedded.PlanEventRequest
	if err := decodeYAML(body, &r); err != nil {
		return nil, statusCodec
	}
	if s := boundedFields(r.Path, r.EventID); s != statusOK {
		return nil, s
	}
	event, err := h.PlanEvent(r)
	if err != nil {
		return nil, statusForError(err)
	}
	return event, statusOK
}

func opEventStart(h *embedded.Handle, body []byte) (interface{}, C.lj_status_t) {
	var r embedded.StartEventRequest
	if err := decodeYAML(body, &r); err != nil {
		return nil, statusCodec
	}
	if s := boundedFields(r.Path, r.EventID); s != statusOK {
		return nil, s
	}
	event, err := h.StartEvent(r)
	if err != nil {
		return nil, statusForError(err)
	}
	return event, statusOK
}

func opEventAppend(h *embedded.Handle, body []byte) (interface{}, C.lj_status_t) {
	var r embedded.AppendEventRequest
	if err := decodeYAML(body, &r); err != nil {
		return nil, statusCodec
	}
	if s := boundedFields(r.Path, r.EventID); s != statusOK {
		return nil, s
	}
	event, err := h.AppendToEvent(r)
	if err != nil {
		return nil, statusForError(err)
	}
	return event, statusOK
}

func opEventEnd(h *embedded.Handle, body []byte) (interface{}, C.lj_status_t) {
	var r embedded.EndEventRequest
	if err := decodeYAML(body, &r); err != nil {
		return nil, statusCodec
	}
	if s := boundedFields(r.Path, r.EventID); s != statusOK {
		return nil, s
	}
	event, err := h.EndEvent(r)
	if err != nil {
		return nil, statusForError(err)
	}
	return event, statusOK
}

func opEventEntries(h *embedded.Handle, body []byte) (interface{}, C.lj_status_t) {
	var r embedded.EventEntriesRequest
	if err := decodeYAML(body, &r); err != nil {
		return nil, statusCodec
	}
	entries, err := h.EventEntries(r)
	if err != nil {
		return nil, statusForError(err)
	}
	return entries, statusOK
}

func opQuery(h *embedded.Handle, body []byte) (interface{}, C.lj_status_t) {
	var r embedded.QueryRequest
	if err := decodeYAML(body, &r); err != nil {
		return nil, statusCodec
	}
	response, err := h.Query(r)
	if err != nil {
		return nil, statusForError(err)
	}
	return response, statusOK
}

func opAggregate(h *embedded.Handle, body []byte) (interface{}, C.lj_status_t) {
	var r embedded.AggregateRequest
	if err := decodeYAML(body, &r); err != nil {
		return nil, statusCodec
	}
	response, err := h.Aggregate(r)
	if err != nil {
		return nil, statusForError(err)
	}
	return response, statusOK
}

func opForest(h *embedded.Handle, _ []byte) (interface{}, C.lj_status_t) {
	return h.Forest(), statusOK
}

// boundedFields refuses a mutation whose identity-bearing fields exceed LJ_MAX_PATH, which is what
// makes the acknowledgement's size provable and LJ_MUTATION_OUT_MIN sufficient. An empty field is
// not checked here — the engine decides whether an empty path or id is valid.
func boundedFields(path, eventID string) C.lj_status_t {
	if len(path) > int(C.LJ_MAX_PATH) || len(eventID) > int(C.LJ_MAX_PATH) {
		return statusTooLarge
	}
	return statusOK
}

// statusError is any error that carries an HTTP status — the engine's apiError does, via its
// exported Status(). Matching on the interface keeps this package clear of internal.
type statusError interface{ Status() int }

// statusForError maps an engine error to a boundary status. The HTTP codes are the ones the engine
// already carries as data; an error with no status of its own is the server's fault and is INTERNAL.
func statusForError(err error) C.lj_status_t {
	if err == nil {
		return statusOK
	}
	var carried statusError
	if errors.As(err, &carried) {
		switch carried.Status() {
		case 400:
			return statusInvalid
		case 403:
			return statusForbidden
		case 404:
			return statusNotFound
		case 409:
			return statusConflict
		case 413:
			return statusTooLarge
		case 429:
			return statusBusy
		case 503:
			return statusClosed
		}
	}
	return statusInternal
}
