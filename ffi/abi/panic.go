// Written by Richard Christopher, Copyright 2026 NeoTec, LLC

//go:build lj_panic_test

package abi

/*
#include "lumberjack.h"
*/
import "C"

// PanicForTest panics inside the guard every export runs under, to prove a panic becomes LJ_PANIC
// and the process lives. It is compiled ONLY under the lj_panic_test tag; see ffi/panic_export.go.
func PanicForTest() (status int32) {
	return int32(panicForTest())
}

func panicForTest() (status C.lj_status_t) {
	defer guard(&status, nil)
	panic("forced panic to exercise the recover guard")
}
