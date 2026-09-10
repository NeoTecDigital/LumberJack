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

// replayBufferSize is a ring capacity, and a ring's capacity is only meaningful at its edge: one
// below it nothing has been evicted, at it nothing has been evicted, and one past it EXACTLY one
// mutation has fallen off the back. Nothing asserted any of the three, so the ring could have been
// off by one in either direction — holding 1023 or 1025 — and every existing test would still pass.
func TestReplayRingHoldsExactlyItsCapacity(t *testing.T) {
	for _, testCase := range []struct {
		published  int
		held       int
		wantOldest uint64
	}{
		{replayBufferSize - 1, replayBufferSize - 1, 1},
		{replayBufferSize, replayBufferSize, 1},
		{replayBufferSize + 1, replayBufferSize, 2},
	} {
		stream := newMutationStream()
		for i := 0; i < testCase.published; i++ {
			stream.publish(mutationEvent{Type: "x"})
		}

		if got := len(stream.recent); got != testCase.held {
			t.Errorf("after %d published the ring holds %d, want %d", testCase.published, got, testCase.held)
		}

		// The ring is a window on a numbering that never rewinds: whatever it dropped, the newest it
		// holds is always the last sequence published.
		_, caughtUp, oldest := stream.pollSince(0)
		if oldest != testCase.wantOldest {
			t.Errorf("after %d published the oldest held sequence is %d, want %d",
				testCase.published, oldest, testCase.wantOldest)
		}
		if newest := stream.recent[len(stream.recent)-1].Sequence; newest != uint64(testCase.published) {
			t.Errorf("after %d published the newest held sequence is %d, want %d",
				testCase.published, newest, testCase.published)
		}
		// A cursor of 0 is caught up until something has actually been evicted, and not after.
		if wantCaughtUp := testCase.published <= replayBufferSize; caughtUp != wantCaughtUp {
			t.Errorf("after %d published pollSince(0) caughtUp=%v, want %v",
				testCase.published, caughtUp, wantCaughtUp)
		}
	}
}

// A GAP's whole worth to a caller is `oldest`: it is where the caller resumes after re-deriving its
// view. Nothing asserted what value it carries — only that it was non-zero — so a ring reporting the
// NEWEST held sequence, or one off by a position, would have satisfied every existing test while
// making a resuming caller skip everything between.
func TestGapReportsTheOldestSequenceARingStillHolds(t *testing.T) {
	const evicted = 7
	stream := newMutationStream()
	for i := 0; i < replayBufferSize+evicted; i++ {
		stream.publish(mutationEvent{Type: "x"})
	}

	events, caughtUp, oldest := stream.pollSince(0)
	if caughtUp || len(events) != 0 {
		t.Fatalf("pollSince(0) = (%d events, caughtUp=%v), want a gap with no replay", len(events), caughtUp)
	}

	// THE VALUE, exactly: evicted+1 mutations were published past the ring's capacity, so sequence
	// evicted+1 is the first one still held.
	if want := uint64(evicted + 1); oldest != want {
		t.Fatalf("gap reported oldest=%d, want %d — a caller resuming from this skips or repeats", oldest, want)
	}
	if oldest != stream.recent[0].Sequence {
		t.Fatalf("gap reported oldest=%d but the ring's first held sequence is %d",
			oldest, stream.recent[0].Sequence)
	}

	// Resuming from it loses nothing: the caller re-derives its view as of `oldest`, then reads
	// forward from oldest-1 and receives every mutation the ring still holds, starting AT oldest.
	replay, caughtUp, _ := stream.pollSince(oldest - 1)
	if !caughtUp {
		t.Fatalf("pollSince(oldest-1) reported a gap; the sequence a gap names must itself be readable")
	}
	if len(replay) != replayBufferSize {
		t.Fatalf("resuming from oldest-1 replayed %d mutations, want the whole ring (%d)",
			len(replay), replayBufferSize)
	}
	if replay[0].Sequence != oldest {
		t.Fatalf("the replay begins at sequence %d, want %d — the gap named a position it does not hand back",
			replay[0].Sequence, oldest)
	}
}
