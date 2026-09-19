// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// A RESEND IS A NEW CODE, NOT A NEW LOGIN ATTEMPT AND NOT A FREE TEXT MESSAGE.
//
// /mfa/start swapped a fresh code into a live challenge and set Attempts back to zero, which handed
// the caller a guess budget it had not earned: four wrong codes, one resend, four more wrong codes,
// for as long as the challenge's five minutes lasted. Every one of those resends also put a fresh
// item on the outbox, so the same call was an SMS tap on the enrolled handset — bounded by nothing
// but the TTL, and reachable by anyone already holding the password and the right last four digits.
//
// These pin the four rules the policy is made of, and the one case it must not break.

// failDelivery stamps the give-up verdict on a challenge, which is what the forward-dispatcher does
// when a carrier refuses for good. It is how a test says "this code never reached a handset" — the
// one condition under which a second code may go out without waiting.
func failDelivery(t *testing.T, server *Server, challengeID string) {
	t.Helper()
	if err := server.changeForest(func() error {
		challenge, ok := server.forest.MFAChallenges[challengeID]
		if !ok {
			t.Fatalf("no challenge %s to report a delivery for", challengeID)
		}
		challenge.Delivery = deliveryFailed
		server.forest.MFAChallenges[challengeID] = challenge
		return nil
	}); err != nil {
		t.Fatalf("recording the failed delivery: %v", err)
	}
}

// backdateSend pushes a challenge's last send into the past, which is how a case says "the user
// waited" without the suite waiting with them. CreatedAt moves too, so the record stays coherent for
// anyone reading it and so the zero-value reading of LastSendAt cannot quietly make the case vacuous.
func backdateSend(t *testing.T, server *Server, challengeID string, seconds int64) {
	t.Helper()
	if err := server.changeForest(func() error {
		challenge, ok := server.forest.MFAChallenges[challengeID]
		if !ok {
			t.Fatalf("no challenge %s to backdate", challengeID)
		}
		challenge.CreatedAt -= seconds
		challenge.LastSendAt = challengeLastSend(challenge) - seconds
		server.forest.MFAChallenges[challengeID] = challenge
		return nil
	}); err != nil {
		t.Fatalf("backdating the send: %v", err)
	}
}

// refusalStatus reads the status off a refusal, failing the test on an error that carries none.
func refusalStatus(t *testing.T, err error) int {
	t.Helper()
	var carried *apiError
	if !asAPIError(err, &carried) {
		t.Fatalf("the refusal carried no status: %v", err)
	}
	return carried.status
}

// enqueuedCode is the plaintext sitting on the outbox for a challenge — the thing a carrier would
// actually be handed. A test watches it to tell "a new text went out" from "nothing did".
func enqueuedCode(t *testing.T, server *Server, challengeID string) string {
	t.Helper()
	return outboundFor(t, server, challengeID).Payload
}

// TestMFAResendDoesNotRestoreASpentGuessBudget is the amplifier itself. The budget belongs to the
// CHALLENGE — this login attempt — and not to the code, so replacing the code cannot give back
// guesses that were already spent against it.
//
// OBSERVED RED (the policy restored to the shape the engine had at cb46866 — mayResend
// returning nil and `challenge.Attempts = 0` back in resendMFAChallenge,
// `go test ./internal -run TestMFAResendDoesNotRestoreASpentGuessBudget -count=1`):
//
//	--- FAIL: TestMFAResendDoesNotRestoreASpentGuessBudget (0.08s)
//	    application_mfa_resend_test.go:116: the resend handed back 4 guesses the caller had already spent
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.084s
func TestMFAResendDoesNotRestoreASpentGuessBudget(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)
	wrong := wrongCode(enqueuedCode(t, server, challengeID))

	for i := 0; i < mfaMaxAttempts-1; i++ {
		if _, err := server.verifyMFAChallenge(token, wrong); err == nil {
			t.Fatalf("wrong guess %d was accepted", i+1)
		}
	}
	if spent := server.forest.MFAChallenges[challengeID].Attempts; spent != mfaMaxAttempts-1 {
		t.Fatalf("the challenge counted %d guesses, want %d", spent, mfaMaxAttempts-1)
	}

	// The resend a user whose code never arrived would make, at the one moment the policy lets it
	// happen straight away.
	failDelivery(t, server, challengeID)
	if err := server.resendMFAChallenge(token); err != nil {
		t.Fatalf("a resend after a failed delivery was refused: %v", err)
	}

	if spent := server.forest.MFAChallenges[challengeID].Attempts; spent != mfaMaxAttempts-1 {
		t.Fatalf("the resend handed back %d guesses the caller had already spent", mfaMaxAttempts-1-spent)
	}
	// And the budget is genuinely gone rather than merely counted: the one guess left is the last one.
	if _, err := server.verifyMFAChallenge(token, wrongCode(enqueuedCode(t, server, challengeID))); err == nil {
		t.Fatal("the last guess was accepted")
	}
	if _, ok := server.forest.MFAChallenges[challengeID]; ok {
		t.Fatal("the challenge outlived its whole guess budget: the resend reset the count")
	}
}

// TestMFAResendIsRefusedInsideTheMinimumInterval is the tap. A resend the instant after a code went
// out cannot be a user reacting to a text that did not arrive — nothing has had time not to arrive —
// and each one costs the enrolled handset a real message.
//
// OBSERVED RED (the same restoration: mayResend returning nil, so nothing enforces an interval,
// `go test ./internal -run TestMFAResendIsRefusedInsideTheMinimumInterval -count=1`):
//
//	--- FAIL: TestMFAResendIsRefusedInsideTheMinimumInterval (0.08s)
//	    application_mfa_resend_test.go:151: a resend one instant after the first code was accepted: the outbox is a tap on the account's phone
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.082s
func TestMFAResendIsRefusedInsideTheMinimumInterval(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)
	first := enqueuedCode(t, server, challengeID)

	refusal := server.resendMFAChallenge(token)
	if refusal == nil {
		t.Fatal("a resend one instant after the first code was accepted: the outbox is a tap on the account's phone")
	}
	if status := refusalStatus(t, refusal); status != http.StatusTooManyRequests {
		t.Errorf("a resend inside the interval answered %d, want %d", status, http.StatusTooManyRequests)
	}
	// NOTHING WENT OUT. The status is the caller's half of it; this is the handset's half.
	if now := enqueuedCode(t, server, challengeID); now != first {
		t.Error("a refused resend still put a fresh code on the outbox: the message went out anyway")
	}
	// And the challenge is untouched — a refused resend is not a failed login.
	if _, err := server.verifyMFAChallenge(token, first); err != nil {
		t.Errorf("a refused resend broke the challenge it refused to extend: %v", err)
	}
}

// TestMFAResendIsRefusedWhenTooLittleOfTheChallengeIsLeft. The expiry is deliberately NOT extended by
// a resend, which is right — a resend must not keep an unfinished login alive forever. The
// consequence is that a code sent near the end arrives already dead, so the message is spent on
// nothing. Refusing it is the same rule read forwards: do not send what cannot be used.
//
// OBSERVED RED (the same restoration: mayResend returning nil, so a resend goes out regardless
// of how little of the challenge is left,
// `go test ./internal -run TestMFAResendIsRefusedWhenTooLittleOfTheChallengeIsLeft -count=1`):
//
//	--- FAIL: TestMFAResendIsRefusedWhenTooLittleOfTheChallengeIsLeft (0.08s)
//	    application_mfa_resend_test.go:198: a resend with 10s left on the challenge was accepted: the code arrives already dead
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.083s
func TestMFAResendIsRefusedWhenTooLittleOfTheChallengeIsLeft(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)
	first := enqueuedCode(t, server, challengeID)

	// Ten seconds left, and a failed delivery so the interval is not what refuses this.
	expiring := server.forest.MFAChallenges[challengeID]
	expiring.ExpiresAt = time.Now().Unix() + 10
	server.forest.MFAChallenges[challengeID] = expiring
	failDelivery(t, server, challengeID)

	refusal := server.resendMFAChallenge(token)
	if refusal == nil {
		t.Fatal("a resend with 10s left on the challenge was accepted: the code arrives already dead")
	}
	if now := enqueuedCode(t, server, challengeID); now != first {
		t.Error("a refused resend still put a fresh code on the outbox")
	}
}

// TestMFAResendIsCappedNoMatterHowOftenDeliveryFails is rule 4, proved at its weakest point. The
// interval is waived when a code demonstrably never landed, so a carrier that keeps refusing is the
// one condition under which resends can come back to back — and it is exactly there that a cap has
// to hold, or the waiver is the tap the interval was closing.
//
// OBSERVED RED (with mayResend's `challengeSends(challenge) >= mfaMaxSends` guard disabled,
// `go test ./internal -run TestMFAResendIsCappedNoMatterHowOftenDeliveryFails -count=1`):
//
//	--- FAIL: TestMFAResendIsCappedNoMatterHowOftenDeliveryFails (0.08s)
//	    application_mfa_resend_test.go:239: send 4 of a 3-send cap was accepted: the outbox is an unbounded tap on the account's phone
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.085s
func TestMFAResendIsCappedNoMatterHowOftenDeliveryFails(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)

	// beginMFAChallenge was send one, so the budget left is the rest of the cap.
	for send := 2; send <= mfaMaxSends; send++ {
		failDelivery(t, server, challengeID)
		if err := server.resendMFAChallenge(token); err != nil {
			t.Fatalf("send %d of a %d-send cap was refused: %v", send, mfaMaxSends, err)
		}
	}

	failDelivery(t, server, challengeID)
	last := enqueuedCode(t, server, challengeID)
	refusal := server.resendMFAChallenge(token)
	if refusal == nil {
		t.Fatalf("send %d of a %d-send cap was accepted: the outbox is an unbounded tap on the account's phone",
			mfaMaxSends+1, mfaMaxSends)
	}
	if status := refusalStatus(t, refusal); status != http.StatusTooManyRequests {
		t.Errorf("a capped resend answered %d, want %d", status, http.StatusTooManyRequests)
	}
	if now := enqueuedCode(t, server, challengeID); now != last {
		t.Error("a capped resend still put a fresh code on the outbox")
	}
	// THE SIGN-IN IS NOT DESTROYED BY THE CAP. The last code that did go out is still the way in, so
	// a user whose third text arrives late has not been locked out by the refusal of a fourth.
	if _, err := server.verifyMFAChallenge(token, last); err != nil {
		t.Errorf("the last code that was actually sent no longer completes the login: %v", err)
	}
}

// TestMFAResendGoesStraightOutWhenTheCodeNeverLanded is rule 3, and it is here to stop a later
// tightening from taking it away. The one person the interval hurts is the one whose code really was
// lost, and the delivery verdict is what tells them apart from someone hammering the button — it is
// written by the forward-dispatcher over the trusted hub and cannot be set by the caller asking for
// the resend.
//
// OBSERVED RED (with mayResend's `challenge.Delivery == deliveryFailed` waiver removed, so the
// interval refuses a code that provably never arrived,
// `go test ./internal -run TestMFAResendGoesStraightOutWhenTheCodeNeverLanded -count=1`):
//
//	--- FAIL: TestMFAResendGoesStraightOutWhenTheCodeNeverLanded (0.08s)
//	    application_mfa_resend_test.go:283: a resend after a reported delivery FAILURE was refused: A code was sent a moment ago; wait 30 seconds before asking for another
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.084s
func TestMFAResendGoesStraightOutWhenTheCodeNeverLanded(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)
	first := enqueuedCode(t, server, challengeID)

	// Nothing has been backdated: this is the same instant the interval refuses in the case above.
	failDelivery(t, server, challengeID)
	if err := server.resendMFAChallenge(token); err != nil {
		t.Fatalf("a resend after a reported delivery FAILURE was refused: %v", err)
	}
	if now := enqueuedCode(t, server, challengeID); now == first {
		t.Fatal("the resend was accepted but queued the same code: nothing new went out")
	}
	// The verdict went back to pending with the new code, or the client polling it would read the old
	// failure and conclude the resend had failed too.
	if verdict := server.forest.MFAChallenges[challengeID].Delivery; verdict != deliveryPending {
		t.Errorf("the replaced code's verdict survived the resend as %q", verdict)
	}
}

// TestMFAResendReplacesTheCodeOnceTheIntervalHasPassed is the ordinary case, and the one a policy
// like this breaks first: a user who waited, asked again, and must get a working code. The old code
// stops working, because two live codes for one challenge would double the guess space the lockout
// is sized against.
//
// OBSERVED RED (with mayResend's interval made unconditional — the `deliveryFailed` waiver removed
// AND the elapsed-time comparison replaced by an outright refusal,
// `go test ./internal -run TestMFAResendReplacesTheCodeOnceTheIntervalHasPassed -count=1`):
//
//	--- FAIL: TestMFAResendReplacesTheCodeOnceTheIntervalHasPassed (0.08s)
//	    application_mfa_resend_test.go:321: a resend well after the interval was refused: A code was sent a moment ago; wait 30 seconds before asking for another
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.083s
func TestMFAResendReplacesTheCodeOnceTheIntervalHasPassed(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	challengeID := challengeIDOf(t, server, token)
	first := enqueuedCode(t, server, challengeID)

	backdateSend(t, server, challengeID, int64(mfaResendInterval.Seconds())+1)
	if err := server.resendMFAChallenge(token); err != nil {
		t.Fatalf("a resend well after the interval was refused: %v", err)
	}

	second := enqueuedCode(t, server, challengeID)
	if second == first {
		t.Fatal("the resend queued the same code")
	}
	if _, err := server.verifyMFAChallenge(token, first); err == nil {
		t.Fatal("the code the resend replaced still completed the login: two live codes for one challenge")
	}
	if _, err := server.verifyMFAChallenge(token, second); err != nil {
		t.Fatalf("the code the resend sent did not complete the login: %v", err)
	}
}

// TestResendRefusalSaysHowLongToWait. writeAPIError used to attach the worker pool's one-second hint
// to EVERY 429 it saw, because there was only ever one; a resend refusal wearing that number tells a
// client to try again twenty-nine seconds before it can work, which is worse than telling it nothing.
//
// OBSERVED RED (with apiError.retryAfter reverted to writeAPIError's old `if status == 429` guess,
// `go test ./internal -run TestResendRefusalSaysHowLongToWait -count=1`):
//
//	--- FAIL: TestResendRefusalSaysHowLongToWait (0.08s)
//	    application_mfa_resend_test.go:374: the resend refusal says Retry-After: "1", which is not this route's wait
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.084s
func TestResendRefusalSaysHowLongToWait(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	token, err := server.beginMFAChallenge(&user)
	if err != nil {
		t.Fatalf("beginMFAChallenge: %v", err)
	}
	refusal := server.resendMFAChallenge(token)
	if refusal == nil {
		t.Fatal("the resend was not refused; there is no refusal to read a hint off")
	}

	recorder := httptest.NewRecorder()
	writeAPIError(recorder, refusal)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("the refusal was written as %d, want %d", recorder.Code, http.StatusTooManyRequests)
	}
	hint := recorder.Header().Get("Retry-After")
	if hint == "" {
		t.Fatal("the resend refusal carries no Retry-After (RFC 6585 §4)")
	}
	seconds, err := strconv.Atoi(hint)
	if err != nil {
		t.Fatalf("Retry-After is not a number of seconds: %q", hint)
	}
	if seconds < 2 || seconds > int(mfaResendInterval.Seconds()) {
		t.Errorf("the resend refusal says Retry-After: %q, which is not this route's wait", hint)
	}
}
