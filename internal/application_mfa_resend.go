// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"net/http"
	"strconv"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// WHAT A RESEND IS ALLOWED TO BE, AND WHAT IT WAS.
//
// /mfa/start swapped a fresh code into a live challenge and set Attempts back to zero. That is two
// separate things given away for free, and both were measured on this engine before the policy
// below existed, in one five-minute challenge, holding nothing but a password and the right last
// four digits:
//
//   - THE GUESS BUDGET CAME BACK. Four wrong codes answered "Invalid code; 1 attempts remaining";
//     one resend put it back to four remaining; seven rounds of that ran twenty-eight guesses at a
//     six-digit space through a lockout built to allow five.
//   - THE HANDSET WAS A TAP. Thirty further back-to-back resends were all accepted, and the outbox
//     took thirty-eight distinct codes — thirty-eight text messages to the enrolled phone, from one
//     stolen password, bounded by nothing but the TTL.
//
// FOUR RULES, AND EACH ANSWERS ONE OF THOSE.
//
//  1. THE GUESS BUDGET DOES NOT COME BACK. Attempts counts guesses against the CHALLENGE — this
//     login attempt — and a resend replaces the code, not the attempt. resendMFAChallenge leaves it
//     alone. A user who genuinely burns all five guesses is where they always were: back at /login,
//     which costs a fresh password and a fresh ownership check, and that is the intended escape.
//
//  2. A MINIMUM INTERVAL BETWEEN SENDS. A resend one instant after a code went out cannot be someone
//     reacting to a text that did not arrive, because nothing has yet had time not to arrive.
//     Thirty seconds is past the point where "the carrier is just slow" is the likely explanation
//     and short enough that a person who is actually waiting is not made to sit through it twice.
//
//  3. UNLESS THE LAST CODE DEMONSTRABLY NEVER LANDED. The delivery verdict makes that observable for
//     the first time, and it is the whole reason the interval can be this strict: when the
//     forward-dispatcher has reported "failed", there is no text in flight to wait for and no
//     handset being messaged, so making the one user whose code really was lost wait anyway would be
//     charging them for a fault that is provably not theirs. A caller cannot forge this — the
//     verdict is written by the trusted hub, never by the party asking for the resend.
//
//  4. A HARD CAP ON SENDS PER CHALLENGE. The interval alone still allows ten texts across a
//     challenge's five minutes, and rule 3 would allow them back to back. Three sends — the original
//     and two more — is more than a working deployment ever needs: a third failure is not a carrier
//     hiccup, it is a broken deployment, and the answer to that is the delivery verdict the client
//     is already polling, not a fourth message. The cap is never waived, including by rule 3,
//     because it is the bound on the whole exchange rather than on how fast it runs.
//
// AND THE EXPIRY IS STILL NOT EXTENDED, which was right and stays right: a resend that pushed the
// expiry out would let an unfinished login be kept alive indefinitely, one code at a time. The cost
// of that is a code posted near the end of the window arriving already dead, so the fifth rule is
// the same one read forwards — do not spend a message on a challenge that cannot be finished with
// it. A minute is the floor, which is comfortably longer than a text takes and comfortably shorter
// than the window it is carved out of.
//
// EVERY REFUSAL HERE IS 429, and that is honest rather than convenient: the caller is holding a
// valid challenge and asking too often, which is neither an authentication failure nor a malformed
// request. It is safe to say so precisely BECAUSE the caller holds a signed mfa_pending bearer for
// this challenge already — nothing here can be reached by guessing a challenge id, so telling the
// holder why it was refused discloses nothing it did not bring with it.
//
// WHAT THIS DOES NOT CLOSE, said plainly so nobody reads a bound here that is not there: /login
// itself still mints a new challenge and a new text on every successful password-plus-last-four, and
// nothing in this file bounds THAT. Bounding it needs a per-ACCOUNT budget that survives a challenge
// being destroyed — a lockout deletes the challenge, and with it any count kept on the challenge —
// and it trades an SMS flood for the ability to block a real user's sign-in. That is a decision
// about the product, not a mechanical one, and it is not made here.
const (
	// mfaResendInterval is rule 2: the shortest gap between two codes for one challenge.
	mfaResendInterval = 30 * time.Second
	// mfaMaxSends is rule 4: how many codes one challenge may ever put on the wire, the first
	// included. THE FIRST IS COUNTED, which is why beginMFAChallenge writes Sends: 1 — a cap that
	// counted only resends would be a different number pretending to be this one.
	mfaMaxSends = 3
	// mfaMinUsableWindow is rule 5: how much of the challenge must be left for a new code to be worth
	// sending. It is well under mfaCodeTTL, so it narrows when a resend may happen and never stops
	// one from happening at all.
	mfaMinUsableWindow = 60 * time.Second
)

// challengeSends is how many codes a challenge has sent, reading the zero value as the truth: a
// challenge cannot exist without the send that created it, so no stored record needs migrating.
func challengeSends(challenge core.MFAChallenge) int {
	if challenge.Sends < 1 {
		return 1
	}
	return challenge.Sends
}

// challengeLastSend is when the most recent code went out, reading the zero value the same way —
// a challenge that has only ever sent once sent it when it was created.
func challengeLastSend(challenge core.MFAChallenge) int64 {
	if challenge.LastSendAt == 0 {
		return challenge.CreatedAt
	}
	return challenge.LastSendAt
}

// mayResend applies the policy above and returns the refusal, or nil to send.
//
// It is PURE — a challenge and a clock in, a decision out — so the rules can be read in one place
// and asserted without a server, and so resendMFAChallenge stays a transaction rather than a policy.
// The order is the order of severity: a cap that is spent and a challenge that is nearly over are
// both "stop asking", and only the interval is "ask again shortly".
func mayResend(challenge core.MFAChallenge, now int64) *apiError {
	if challengeSends(challenge) >= mfaMaxSends {
		return apiErrorf(http.StatusTooManyRequests,
			"No more codes can be sent for this sign-in; start again to get a new one")
	}
	if challenge.ExpiresAt-now < int64(mfaMinUsableWindow.Seconds()) {
		return apiErrorf(http.StatusTooManyRequests,
			"This sign-in is nearly over; start again to get a new code")
	}
	// Rule 3. The verdict belongs to the code being replaced, and "failed" is the dispatcher saying
	// that code reached nobody — so there is no message in flight that waiting would let arrive.
	if challenge.Delivery == deliveryFailed {
		return nil
	}
	if wait := challengeLastSend(challenge) + int64(mfaResendInterval.Seconds()) - now; wait > 0 {
		return apiErrorRetryAfter(http.StatusTooManyRequests, strconv.FormatInt(wait, 10),
			"A code was sent a moment ago; wait %d seconds before asking for another", wait)
	}
	return nil
}

// recordResend books the send the policy just allowed. It is called INSIDE the exclusive hold, on
// the copy that is about to be written back, so the count and the code it counts are one snapshot —
// a send that is remembered only after a flush is a send the cap can be talked out of by a crash.
func recordResend(challenge *core.MFAChallenge, now int64) {
	challenge.Sends = challengeSends(*challenge) + 1
	challenge.LastSendAt = now
}
