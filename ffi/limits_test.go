// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The boundary arithmetic of the ABI, tested at and just past the widths that failed before v2.
//
// None of these allocate a multi-gigabyte buffer. The defects were in the ARITHMETIC — a length
// narrowed to 32 bits, a duration multiplied past int64 — so the fixes are pure functions of a
// size and a cap, and the tests drive those functions with the exact boundary values a real 2 GiB
// document or a nonsense timeout would have produced. Each asserts the value the OLD width computed
// (a negative length, an instant timeout) is NOT what comes back.
package main

import (
	"math"
	"testing"
	"time"
)

// answerPlan is what silently truncated a document at 2^31 into a whole one. In int64 the size is
// preserved and the document is correctly classified as not fitting.
func TestAnswerPlanDoesNotNarrowAtTwoGiB(t *testing.T) {
	twoGiB := int64(1) << 31 // where int32 wraps to its most negative value

	report, status := answerPlan(twoGiB, 4096)
	if report != twoGiB {
		t.Fatalf("report = %d, want %d; a 32-bit out_len would have reported %d", report, twoGiB, int32(twoGiB))
	}
	if status != statusTruncated {
		t.Fatalf("status = %d, want LJ_TRUNCATED (%d); the narrowed negative compared below out_cap and returned LJ_OK (%d)",
			status, statusTruncated, statusOK)
	}

	// 2^32 + 100 against a 100-byte buffer. The low 32 bits are exactly 100, so a 32-bit width told
	// the caller its 100-byte buffer held the whole document while the rest was clobbered.
	past4GiB := (int64(1) << 32) + 100
	report, status = answerPlan(past4GiB, 100)
	if report != past4GiB {
		t.Fatalf("report = %d, want %d; a 32-bit out_len would have reported %d", report, past4GiB, int32(past4GiB))
	}
	if status != statusTruncated {
		t.Fatalf("status = %d, want LJ_TRUNCATED for a 4 GiB document in a 100-byte buffer", status)
	}
}

// answerPlan still answers LJ_OK when the document genuinely fits, at the exact boundary out_cap ==
// docLen — the fix must not turn every large-but-fitting answer into a truncation.
func TestAnswerPlanFitsExactlyAtCapacity(t *testing.T) {
	if report, status := answerPlan(4096, 4096); status != statusOK || report != 4096 {
		t.Fatalf("answerPlan(4096, 4096) = (%d, %d), want (4096, LJ_OK)", report, status)
	}
	if _, status := answerPlan(4097, 4096); status != statusTruncated {
		t.Fatalf("answerPlan(4097, 4096) status = %d, want LJ_TRUNCATED one byte over", status)
	}
}

// take refuses a request past the inbound cap BEFORE it allocates or dereferences the pointer, so a
// caller cannot demand a multi-gigabyte Go allocation per call. The discriminating pair: an
// over-cap length with a nil pointer reports LJ_TOO_LARGE (the bound trips first), while an
// in-range length with the same nil pointer reports LJ_INVALID (the pointer check is reached). With
// the bound removed BOTH would report LJ_INVALID, so the flip to LJ_TOO_LARGE is the fix itself.
func TestTakeRefusesPastTheInboundCap(t *testing.T) {
	if body, status := take(nil, maxTakeLen+1); status != statusTooLarge || body != nil {
		t.Fatalf("take(nil, maxTakeLen+1) = (%v, %d), want (nil, LJ_TOO_LARGE=%d)", body, status, statusTooLarge)
	}
	if _, status := take(nil, 1); status != statusInvalid {
		t.Fatalf("take(nil, 1) status = %d, want LJ_INVALID — an in-range length must reach the pointer check", status)
	}
	if _, status := take(nil, math.MaxInt64); status != statusTooLarge {
		t.Fatalf("take(nil, MaxInt64) status = %d, want LJ_TOO_LARGE — the widest int64 must not slip the cap", status)
	}
}

// take's negative and zero guards are unchanged by the widening: a negative length is refused, and a
// zero length is an empty read, not an error.
func TestTakePreservesNegativeAndZeroGuards(t *testing.T) {
	if _, status := take(nil, -1); status != statusInvalid {
		t.Fatalf("take(nil, -1) status = %d, want LJ_INVALID", status)
	}
	if body, status := take(nil, 0); status != statusOK || body != nil {
		t.Fatalf("take(nil, 0) = (%v, %d), want (nil, LJ_OK)", body, status)
	}
}

// pollTimeout caps a poll's block so an overflowing timeout_ms cannot become a negative duration —
// an instant return — nor pin a thread arbitrarily long. Without the cap, MaxInt64 milliseconds
// times time.Millisecond overflows int64 into a negative duration, which is the bug.
func TestPollTimeoutCapsAnOverflowingRequest(t *testing.T) {
	d, status := pollTimeout(math.MaxInt64)
	if status != statusOK {
		t.Fatalf("pollTimeout(MaxInt64) status = %d, want LJ_OK (clamped, not refused)", status)
	}
	if d <= 0 {
		t.Fatalf("pollTimeout(MaxInt64) = %v, want a positive duration; the unbounded multiply overflows to negative", d)
	}
	if want := time.Duration(maxPollTimeoutMS) * time.Millisecond; d != want {
		t.Fatalf("pollTimeout(MaxInt64) = %v, want it clamped to %v", d, want)
	}
}

// statusOnlyErr carries just an HTTP status, standing in for the engine's apiError so statusForError
// can be driven at the boundary without importing internal.
type statusOnlyErr int

func (e statusOnlyErr) Error() string { return "status-only error" }
func (e statusOnlyErr) Status() int   { return int(e) }

// A saturated pool (429) and a tearing-down runtime (503) are distinct conditions and must not
// collapse to one status. Without the 429 branch a busy server reports LJ_CLOSED — "closing
// underneath this call" — for a runtime that is merely momentarily full and wants a retry.
func TestStatusForErrorMapsBusyApartFromClosed(t *testing.T) {
	if got := statusForError(statusOnlyErr(429)); got != statusBusy {
		t.Fatalf("statusForError(429) = %d, want LJ_BUSY (%d); without the 429 branch a busy pool falls through to LJ_INTERNAL", got, statusBusy)
	}
	if got := statusForError(statusOnlyErr(503)); got != statusClosed {
		t.Fatalf("statusForError(503) = %d, want LJ_CLOSED (%d)", got, statusClosed)
	}
}

// pollTimeout refuses a negative timeout as nonsense and passes an in-range one through untouched.
func TestPollTimeoutRefusesNegativeAndPassesInRange(t *testing.T) {
	if _, status := pollTimeout(-1); status != statusInvalid {
		t.Fatalf("pollTimeout(-1) status = %d, want LJ_INVALID", status)
	}
	if d, status := pollTimeout(0); status != statusOK || d != 0 {
		t.Fatalf("pollTimeout(0) = (%v, %d), want (0, LJ_OK)", d, status)
	}
	if d, status := pollTimeout(250); status != statusOK || d != 250*time.Millisecond {
		t.Fatalf("pollTimeout(250) = (%v, %d), want (250ms, LJ_OK)", d, status)
	}
}
