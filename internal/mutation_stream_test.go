// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The ring's cursor arithmetic at the top of the uint64 range, where after+1 wrapped.
package internal

import (
	"math"
	"testing"
)

// A cursor at the very top of the uint64 range must not be read through a wrapped after+1.
// pollRequest.After is a uint64 straight off the wire, so a Rust caller reaches this value. The old
// `oldest > after+1` was wrong at EXACTLY ONE cursor — 2^64-1, where after+1 wraps to 0 and
// `oldest > 0` reports a permanent false LJ_GAP for a caller that is simply ahead of the ring. Every
// other cursor, 2^64-2 included, was already correct; this is the single case the fix changes.
func TestPollSinceDoesNotWrapAtCursorMax(t *testing.T) {
	stream := newMutationStream()
	for i := 0; i < 3; i++ {
		stream.publish(mutationEvent{Type: "x"}) // sequences 1, 2, 3
	}

	// THE DISCRIMINATOR: on HEAD's form this returned caughtUp=false (the wrapped false gap). The fix
	// makes it caughtUp=true with nothing new — the caller is ahead of the ring, not behind it.
	events, caughtUp, _ := stream.pollSince(math.MaxUint64)
	if !caughtUp {
		t.Fatalf("pollSince(MaxUint64) caughtUp=false: after+1 wrapped to 0 and reported a permanent false gap")
	}
	if len(events) != 0 {
		t.Fatalf("pollSince(MaxUint64) returned %d events, want 0", len(events))
	}

	// CONTROL (passes on both forms): the adjacent cursor 2^64-2 was already correct — caught up with
	// nothing new — so it must stay that way. It is here to show the fix moved only the one value
	// above, not this neighbour.
	events, caughtUp, _ = stream.pollSince(math.MaxUint64 - 1)
	if !caughtUp || len(events) != 0 {
		t.Fatalf("pollSince(MaxUint64-1) = (%d events, caughtUp=%v), want (0, true) unchanged", len(events), caughtUp)
	}
}

// The fix subtracts from oldest instead of adding to after, which is only underflow-safe because the
// ring numbers its first mutation 1 (so oldest is at least 1 whenever it is non-empty). Nothing else
// asserts that invariant, and if publish ever numbered from 0 the fix would underflow to 2^64-1 and
// resurrect the bug — so pin it.
func TestFirstPublishedSequenceIsOne(t *testing.T) {
	stream := newMutationStream()
	first := stream.publish(mutationEvent{Type: "x"})
	if first.Sequence != 1 {
		t.Fatalf("first published sequence = %d, want 1: oldest-1 in replaySince relies on this to not underflow", first.Sequence)
	}
	if stream.recent[0].Sequence != 1 {
		t.Fatalf("ring's oldest held sequence = %d, want 1", stream.recent[0].Sequence)
	}
}

// The fix must not blind the ring to a REAL gap. After eviction has advanced the oldest held
// sequence, a cursor whose next expected sequence has fallen off the back is still a gap, and a
// cursor exactly at the boundary (oldest-1) is still caught up.
func TestPollSinceStillReportsARealGap(t *testing.T) {
	stream := newMutationStream()
	for i := 0; i < replayBufferSize+5; i++ {
		stream.publish(mutationEvent{Type: "x"})
	}

	_, caughtUp, oldest := stream.pollSince(0)
	if caughtUp {
		t.Fatalf("pollSince(0) after eviction caughtUp=true, want a gap — sequence 1 has fallen off the back")
	}
	if oldest == 0 {
		t.Fatalf("a gap must carry the oldest still-held sequence to resume from, got 0")
	}

	if _, caughtUp, _ = stream.pollSince(oldest - 1); !caughtUp {
		t.Fatalf("pollSince(oldest-1) caughtUp=false, want caught up: its next expected sequence is oldest itself")
	}
}
