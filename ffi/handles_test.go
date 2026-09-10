// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The handle table, which had no tests at all.
//
// It is the whole of the ABI's memory safety story: the header promises C a TOKEN that is never an
// address, never recycled, and whose staleness is a clean LJ_BAD_HANDLE rather than somebody else's
// forest. Nothing checked any of that, and the properties are not observable from C — a C caller
// cannot see that a token was reused, only that its call answered.
//
// These are ordinary Go tests because cgo is not supported in test files; the table itself is plain
// Go, so all of it is reachable from here.
package main

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/NeoTecDigital/LumberJack/embedded"
	"github.com/NeoTecDigital/LumberJack/types"
)

// openHandle opens a real runtime over a private temp directory and registers it, returning the
// token and the handle behind it.
func openHandle(t *testing.T) (uint64, *embedded.Handle) {
	t.Helper()
	handle, err := embedded.Open(embedded.Config{
		Process: types.ProcessInfo{Name: "ffi_handles_test", DatabasePath: t.TempDir()},
	}, "system")
	if err != nil {
		t.Fatalf("embedded.Open: %v", err)
	}
	token := registerHandle(handle)
	t.Cleanup(func() {
		if dropped, ok := dropHandle(token); ok {
			dropped.Close()
		}
	})
	return token, handle
}

// ZERO IS NEVER A VALID HANDLE. The counter is incremented before it is handed out, so the first
// token is 1 — which is what makes a zeroed lj_handle_t, the most ordinary C mistake there is, a
// clean refusal instead of a hit on whatever was registered first.
func TestTokenZeroIsNeverRegistered(t *testing.T) {
	if handle, ok := lookupHandle(0); ok {
		t.Fatalf("token 0 resolved to %v; a caller that passed a zeroed handle would be served", handle)
	}

	token, _ := openHandle(t)
	if token == 0 {
		t.Fatal("registerHandle issued token 0")
	}
	if _, ok := lookupHandle(0); ok {
		t.Fatal("token 0 resolves once something has been registered")
	}
}

// A CLOSED TOKEN IS NEVER REUSED. This is the property the header makes load-bearing and the reason
// the token is a monotonic counter rather than a runtime/cgo.Handle, whose slots CAN be reused after
// Delete: a stale token must fail to resolve, never alias a runtime opened afterwards.
func TestAClosedTokenIsNeverIssuedAgain(t *testing.T) {
	first, firstHandle := openHandle(t)
	if _, ok := lookupHandle(first); !ok {
		t.Fatal("a freshly registered token does not resolve")
	}

	dropped, ok := dropHandle(first)
	if !ok || dropped != firstHandle {
		t.Fatalf("dropHandle returned (%v, %v), want the handle that was registered", dropped, ok)
	}
	dropped.Close()

	// The stale token misses. It does not resolve to anything, and it does not resolve to the NEXT
	// runtime either.
	if _, ok := lookupHandle(first); ok {
		t.Fatal("a dropped token still resolves")
	}

	// Fifty more opens, and not one of them answers to the dead token.
	for i := 0; i < 50; i++ {
		next, _ := openHandle(t)
		if next == first {
			t.Fatalf("token %d was issued again after being closed; a stale C handle now aliases a "+
				"live runtime", first)
		}
		if next <= first {
			t.Fatalf("token %d was issued after %d; the counter must never rewind", next, first)
		}
	}
	if _, ok := lookupHandle(first); ok {
		t.Fatal("the dead token resolves again after later runtimes were opened")
	}
}

// TWO HANDLES AT ONCE resolve to their own runtimes and neither drop disturbs the other. A host
// acting over two archives, which is the reason the table is a map and not a single slot.
func TestTwoHandlesResolveIndependently(t *testing.T) {
	first, firstHandle := openHandle(t)
	second, secondHandle := openHandle(t)

	if first == second {
		t.Fatal("two Opens were issued the same token")
	}
	if got, _ := lookupHandle(first); got != firstHandle {
		t.Error("the first token does not resolve to the first handle")
	}
	if got, _ := lookupHandle(second); got != secondHandle {
		t.Error("the second token does not resolve to the second handle")
	}

	dropped, ok := dropHandle(first)
	if !ok {
		t.Fatal("dropping the first token missed")
	}
	dropped.Close()

	if _, ok := lookupHandle(first); ok {
		t.Error("the dropped token still resolves")
	}
	if got, _ := lookupHandle(second); got != secondHandle {
		t.Error("dropping one token disturbed the other")
	}
}

// DROPPING TWICE misses the second time, which is exactly what makes ic_lj_close idempotent: a miss
// is LJ_OK and closing a token twice is benign. If the second drop hit, it would return a handle
// whose Close would run again — and a second decref would steal a reference another handle holds.
func TestDroppingATokenTwiceMissesTheSecondTime(t *testing.T) {
	token, _ := openHandle(t)

	dropped, ok := dropHandle(token)
	if !ok {
		t.Fatal("the first drop missed")
	}
	dropped.Close()

	if again, ok := dropHandle(token); ok {
		t.Fatalf("the second drop returned %v; a close would run twice on one handle", again)
	}
	if _, ok := dropHandle(^uint64(0)); ok {
		t.Fatal("a token that was never issued resolved")
	}
}

// A CALL RACING A CLOSE. Concurrent lookups against a concurrent drop must be a clean hit or a clean
// miss, never a torn read of the map — which is the one failure recover cannot contain, because a
// concurrent map access is a runtime throw and not a panic (see guard's own note in main.go).
//
// The race detector is the assertion. What it is watching is handleMu doing its job.
func TestLookupsRacingACloseAreCleanHitsOrMisses(t *testing.T) {
	const handles = 8
	const readers = 8

	tokens := make([]uint64, handles)
	for i := range tokens {
		tokens[i], _ = openHandle(t)
	}

	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)

	var hits, misses atomic.Int64
	for r := 0; r < readers; r++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			for i := 0; i < 200; i++ {
				for _, token := range tokens {
					if handle, ok := lookupHandle(token); ok {
						if handle == nil {
							panic("lookupHandle reported a hit with a nil handle")
						}
						hits.Add(1)
					} else {
						misses.Add(1)
					}
				}
			}
		}()
	}

	// The closers, racing the readers over the very same tokens.
	for i, token := range tokens {
		done.Add(1)
		go func(n int, tok uint64) {
			defer done.Done()
			start.Wait()
			if handle, ok := dropHandle(tok); ok {
				handle.Close()
			}
		}(i, token)
	}

	start.Done()
	done.Wait()

	if hits.Load() == 0 {
		t.Error("no lookup ever hit; the race did not exercise the live side")
	}
	if misses.Load() == 0 {
		t.Error("no lookup ever missed; the race did not exercise the closed side")
	}
	// Every token is gone afterwards, exactly once each.
	for _, token := range tokens {
		if _, ok := lookupHandle(token); ok {
			t.Errorf("token %d survived its close", token)
		}
	}
}

// CONCURRENT REGISTRATION issues distinct tokens. registerHandle takes its number from an atomic
// counter and files it under a mutex; two openers must never be handed the same one, because a
// duplicate token is two C callers sharing one runtime and one of them closing it.
func TestConcurrentRegistrationIssuesDistinctTokens(t *testing.T) {
	handle, err := embedded.Open(embedded.Config{
		Process: types.ProcessInfo{Name: "ffi_handles_test", DatabasePath: t.TempDir()},
	}, "system")
	if err != nil {
		t.Fatalf("embedded.Open: %v", err)
	}
	defer handle.Close()

	const registrars = 64
	issued := make([]uint64, registrars)

	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for i := 0; i < registrars; i++ {
		done.Add(1)
		go func(n int) {
			defer done.Done()
			start.Wait()
			issued[n] = registerHandle(handle)
		}(i)
	}
	start.Done()
	done.Wait()

	seen := map[uint64]int{}
	for i, token := range issued {
		if token == 0 {
			t.Fatalf("registrar %d was issued token 0", i)
		}
		if first, duplicate := seen[token]; duplicate {
			t.Fatalf("token %d was issued to registrars %d and %d", token, first, i)
		}
		seen[token] = i
	}

	for _, token := range issued {
		if _, ok := lookupHandle(token); !ok {
			t.Fatalf("token %d does not resolve after concurrent registration", token)
		}
		dropHandle(token)
	}
}

// THE TABLE GROWS WITHOUT BOUND when a caller never closes, and there is nothing that reclaims an
// entry. That is the correct trade — a token that expired on its own would be a use-after-free the
// caller cannot see coming — but it is a real cost, and a host that opens per request and never
// closes has an unbounded map.
//
// RECORDED, NOT ENDORSED: a change that added reclamation would break the never-recycled property
// above, so this is here to say the cost is known rather than to defend it.
func TestUnclosedHandlesAccumulateInTheTable(t *testing.T) {
	handle, err := embedded.Open(embedded.Config{
		Process: types.ProcessInfo{Name: "ffi_handles_test", DatabasePath: t.TempDir()},
	}, "system")
	if err != nil {
		t.Fatalf("embedded.Open: %v", err)
	}
	defer handle.Close()

	before := tableSize()
	const leaked = 500
	tokens := make([]uint64, 0, leaked)
	for i := 0; i < leaked; i++ {
		tokens = append(tokens, registerHandle(handle))
	}

	if got := tableSize() - before; got != leaked {
		t.Fatalf("the table grew by %d after %d registrations, want %d — nothing reclaims an entry",
			got, leaked, leaked)
	}
	// Every one of them still resolves, however long ago it was opened.
	for _, token := range tokens {
		if _, ok := lookupHandle(token); !ok {
			t.Fatalf("token %d was reclaimed; a C caller holding it would have been handed a "+
				"LJ_BAD_HANDLE for a runtime that is still open", token)
		}
	}

	for _, token := range tokens {
		dropHandle(token)
	}
	if got := tableSize(); got != before {
		t.Fatalf("the table holds %d entries after every token was dropped, want %d", got, before)
	}
}

// tableSize reads the handle table's size under its own lock, the way the package does.
func tableSize() int {
	handleMu.RLock()
	defer handleMu.RUnlock()
	return len(handles)
}

// A registered handle is the very handle that comes back, not a copy — the table maps a token to the
// ONE runtime it names, and a call through the token must reach that runtime's forest.
func TestALookedUpHandleIsTheRuntimeItNames(t *testing.T) {
	token, handle := openHandle(t)

	if _, err := handle.CreateNode(embedded.CreateNodeRequest{Path: "work/site", Type: "leaf"}); err != nil {
		t.Fatalf("write through the handle: %v", err)
	}

	looked, ok := lookupHandle(token)
	if !ok {
		t.Fatal("the token does not resolve")
	}
	if looked != handle {
		t.Fatal("lookupHandle returned a different handle than was registered")
	}
	if _, err := looked.StartEvent(embedded.StartEventRequest{Path: "work/site", EventID: "e1"}); err != nil {
		t.Fatalf("the looked-up handle does not reach the forest the registered one wrote to: %v", err)
	}
}

// Distinct runtimes stay distinct through the table: a write through one token is not visible
// through another, so a token cannot be handed somebody else's forest.
func TestTokensDoNotCrossBetweenForests(t *testing.T) {
	firstToken, _ := openHandle(t)
	secondToken, _ := openHandle(t)

	first, _ := lookupHandle(firstToken)
	second, _ := lookupHandle(secondToken)

	if _, err := first.CreateNode(embedded.CreateNodeRequest{Path: "only/in/first", Type: "leaf"}); err != nil {
		t.Fatalf("write through the first token: %v", err)
	}

	if _, err := second.StartEvent(embedded.StartEventRequest{
		Path: "only/in/first", EventID: "e1",
	}); err == nil {
		t.Fatal("a node written through one token is reachable through another's forest")
	}

	// And the first still has it, so the refusal above is separation and not a lost write.
	if _, err := first.StartEvent(embedded.StartEventRequest{Path: "only/in/first", EventID: "e1"}); err != nil {
		t.Fatalf("the first token lost the node it wrote: %v", err)
	}
}
