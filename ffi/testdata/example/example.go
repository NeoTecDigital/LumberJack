// Written by Richard Christopher, Copyright 2026 NeoTec, LLC

// Command example is a product archive in miniature (docs/extension-api.md §6): the generated base
// wrappers, one export of its own, and an extension registered before any caller can reach an
// export. `make product-archive-example` builds it as a C archive and drives it from C, which proves
// the composition — one Go runtime, base and product exports in one archive — and that the product
// export resolves the handles ic_lj_open issued.
package main

/*
#include "lumberjack_example.h"
*/
import "C"

import (
	"context"
	"sync/atomic"

	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/ffi/abi"
)

// writes counts the writes the extension's hook saw, across every open forest.
var writes atomic.Int64

// counter is the example's extension: a write hook that counts.
type counter struct{}

func (counter) Spec() extension.Spec { return extension.Spec{Name: "example-counter"} }

func (counter) Attach(extension.Host) (extension.Instance, error) { return counter{}, nil }

func (counter) Close(context.Context) error { return nil }

func (counter) BeforeChangeLocked(extension.Tx, extension.WriteOp) (extension.After, error) {
	writes.Add(1)
	return nil, nil
}

func init() { abi.Register(counter{}) }

//export ic_lj_example_writes
func ic_lj_example_writes(h C.lj_handle_t, out *C.int64_t) C.lj_status_t {
	if out == nil {
		return C.LJ_INVALID
	}
	if _, open := abi.Lookup(uint64(h)); !open {
		return C.LJ_BAD_HANDLE
	}
	*out = C.int64_t(writes.Load())
	return C.LJ_OK
}

func main() {}
