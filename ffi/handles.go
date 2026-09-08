// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The handle table: the map from an opaque token to the runtime it names.
//
// The token is a monotonic counter, NEVER a cgo.Handle and never an address. It never rewinds
// (handleIdx.Add(1)) and a closed token is never reused, so a stale token cannot alias a live
// runtime — a lookup for it simply misses, and the caller is told LJ_BAD_HANDLE rather than handed
// somebody else's forest. A close is lenient (a miss is LJ_OK, so closing twice is fine); every data
// call is strict (a miss is LJ_BAD_HANDLE), which is the asymmetry the header describes.
package main

import (
	"sync"
	"sync/atomic"

	"github.com/NeoTecDigital/LumberJack/embedded"
)

var (
	handleMu  sync.RWMutex
	handles   = map[uint64]*embedded.Handle{}
	handleIdx atomic.Uint64
)

// registerHandle files an open handle under a fresh token and returns it. The first token is 1, so 0
// is never a valid handle — a caller that passes a zeroed token is refused rather than served.
func registerHandle(handle *embedded.Handle) uint64 {
	id := handleIdx.Add(1)
	handleMu.Lock()
	handles[id] = handle
	handleMu.Unlock()
	return id
}

// lookupHandle resolves a token to its handle, or reports that there is none.
func lookupHandle(id uint64) (*embedded.Handle, bool) {
	handleMu.RLock()
	defer handleMu.RUnlock()
	handle, ok := handles[id]
	return handle, ok
}

// dropHandle removes a token from the table and returns the handle it named, if any. The token is
// not recycled, so nothing opened later can ever answer to it again.
func dropHandle(id uint64) (*embedded.Handle, bool) {
	handleMu.Lock()
	defer handleMu.Unlock()
	handle, ok := handles[id]
	if ok {
		delete(handles, id)
	}
	return handle, ok
}
