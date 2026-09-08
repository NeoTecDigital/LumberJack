// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

//go:build lj_panic_test

// A forced-panic export, compiled ONLY under the lj_panic_test build tag.
//
// It exists to prove the guard: that a panic in an export becomes LJ_PANIC and a live process,
// rather than a dead one. It is behind a tag so the shipped archive does not carry it — `nm` over
// build/liblumberjack.a finds no ic_lj__panic_for_test, which the Makefile asserts. The double
// underscore says the same thing to anyone reading the symbol table: this is not part of the ABI.
package main

/*
#include "lumberjack.h"
*/
import "C"

//export ic_lj__panic_for_test
func ic_lj__panic_for_test() (status C.lj_status_t) {
	defer guard(&status, nil)
	panic("forced panic to exercise the recover guard")
}
