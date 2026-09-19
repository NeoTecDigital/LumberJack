// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"strings"
	"testing"
)

// POST /mfa/delivery, and what it is allowed to say.
//
// The route exists so a browser that has been told "we sent a code" can find out whether that is
// still true. Everything below is either the answer it gives or a thing it must NOT give: no phone,
// no code, no username, no failure class, and no way to burn a guess.

// deliveryState drives the route through the REAL routing table, not the handler, because half of
// what is asserted here — that an anonymous caller reaches it at all — lives in the table.
func deliveryState(t *testing.T, server *Server, challenge string) (int, map[string]interface{}, string) {
	t.Helper()
	recorder := serve(t, server, jsonRequest(t, "POST", "/mfa/delivery",
		map[string]interface{}{"challenge": challenge}))
	body := recorder.Body.String()
	var answer map[string]interface{}
	_ = json.Unmarshal([]byte(body), &answer)
	return recorder.Code, answer, body
}

// mfaChallengeInFlight logs a seeded MFA account in and hands back the bearer and the id behind it.
func mfaChallengeInFlight(t *testing.T, server *Server) (string, string) {
	t.Helper()
	user := addMFAUser(t, server)
	body := login(t, server, map[string]interface{}{
		"username": user.Username, "password": "securepass123", "phone_last4": "5309",
	})
	if body.status != 200 {
		t.Fatalf("MFA login answered %d, want 200", body.status)
	}
	token, ok := body.json["challenge"].(string)
	if !ok || token == "" {
		t.Fatalf("the login answered no challenge: %v", body.json)
	}
	return token, challengeIDOf(t, server, token)
}

// TestMfaDeliveryReportsPendingSentAndFailed is the route's whole job: the three states a waiting
// client can act on, each read back from what the hub actually wrote.
//
// OBSERVED RED, part one — the route was not in the table, so the router 404'd the anonymous caller
// before any handler ran (`go test ./internal -run TestMfaDelivery -count=1`):
//
//	--- FAIL: TestMfaDeliveryReportsPendingSentAndFailed (0.34s)
//	    --- FAIL: TestMfaDeliveryReportsPendingSentAndFailed/a_queued_code_reads_pending (0.11s)
//	        application_mfa_delivery_test.go:76: a fresh challenge answered 404 (404 page not found): the route the client polls is not reachable
//	    --- FAIL: TestMfaDeliveryReportsPendingSentAndFailed/a_given-up_code_reads_failed (0.11s)
//	        application_mfa_delivery_test.go:92: the route reports %!q(<nil>) after the dispatcher gave up: the browser waits forever for a code nobody will send
//	    --- FAIL: TestMfaDeliveryReportsPendingSentAndFailed/a_delivered_code_reads_sent (0.11s)
//	        application_mfa_delivery_test.go:105: the route reports %!q(<nil>) for a delivered code, so a client cannot stop asking
//	--- FAIL: TestMfaDeliveryAnswersTheStateAndNothingElse (0.11s)
//	    application_mfa_delivery_test.go:124: polling a live challenge answered 404
//	--- FAIL: TestMfaDeliveryRefusesAJunkChallengeAndSpendsNoGuess (0.11s)
//	    application_mfa_delivery_test.go:146: a junk challenge answered 404, want 401
//	FAIL
//
// OBSERVED RED, part two — with the route registered, `state = challenge.Delivery` in
// challengeDelivery replaced by `_ = challenge`, which is the world as it was before this slice:
// nothing recorded a verdict, so everything looked pending forever. The line was restored
// byte-identically afterwards.
//
//	--- FAIL: TestMfaDeliveryReportsPendingSentAndFailed (0.34s)
//	    --- FAIL: TestMfaDeliveryReportsPendingSentAndFailed/a_given-up_code_reads_failed (0.11s)
//	        application_mfa_delivery_test.go:92: the route reports "pending" after the dispatcher gave up: the browser waits forever for a code nobody will send
//	    --- FAIL: TestMfaDeliveryReportsPendingSentAndFailed/a_delivered_code_reads_sent (0.11s)
//	        application_mfa_delivery_test.go:105: the route reports "pending" for a delivered code, so a client cannot stop asking
//	--- FAIL: TestMfaDeliveryAnswersTheStateAndNothingElse (0.11s)
//	    application_mfa_delivery_test.go:127: the answer is not {mfa_required, delivery}: {"delivery":"pending","mfa_required":true}
//	FAIL
func TestMfaDeliveryReportsPendingSentAndFailed(t *testing.T) {
	t.Run("a queued code reads pending", func(t *testing.T) {
		server, _ := newStockServer(t)
		token, _ := mfaChallengeInFlight(t, server)

		status, answer, raw := deliveryState(t, server, token)
		if status != 200 {
			t.Fatalf("a fresh challenge answered %d (%s): the route the client polls is not reachable", status, strings.TrimSpace(raw))
		}
		if answer["delivery"] != "pending" {
			t.Fatalf("a queued code reads %v, want \"pending\"", answer["delivery"])
		}
	})

	t.Run("a given-up code reads failed", func(t *testing.T) {
		server, _ := newStockServer(t)
		token, challengeID := mfaChallengeInFlight(t, server)
		hubOut(t, server, map[string]interface{}{
			"operation": "outbound_failed", "id": challengeID, "error_class": "auth", "attempts": 1,
		})

		_, answer, _ := deliveryState(t, server, token)
		if answer["delivery"] != "failed" {
			t.Fatalf("the route reports %q after the dispatcher gave up: the browser waits forever for a code nobody will send", answer["delivery"])
		}
	})

	t.Run("a delivered code reads sent", func(t *testing.T) {
		server, _ := newStockServer(t)
		token, challengeID := mfaChallengeInFlight(t, server)
		hubOut(t, server, map[string]interface{}{
			"operation": "outbound_ack", "id": challengeID, "outcome": "sent",
		})

		_, answer, _ := deliveryState(t, server, token)
		if answer["delivery"] != "sent" {
			t.Fatalf("the route reports %q for a delivered code, so a client cannot stop asking", answer["delivery"])
		}
	})
}

// TestMfaDeliveryAnswersTheStateAndNothingElse is the disclosure bound. The engine stores the
// failure class and the attempt count beside the verdict because an OPERATOR needs them; the caller
// holding a challenge does not, and "the provider's credentials are missing" is a fact about this
// deployment. The phone, the code and the username are never near this route at all.
func TestMfaDeliveryAnswersTheStateAndNothingElse(t *testing.T) {
	server, _ := newStockServer(t)
	token, challengeID := mfaChallengeInFlight(t, server)
	code := outboundFor(t, server, challengeID).Payload
	hubOut(t, server, map[string]interface{}{
		"operation": "outbound_failed", "id": challengeID, "error_class": "auth", "attempts": 3,
	})

	status, answer, raw := deliveryState(t, server, token)
	if status != 200 {
		t.Fatalf("polling a live challenge answered %d", status)
	}
	if len(answer) != 2 || answer["mfa_required"] != true || answer["delivery"] != "failed" {
		t.Fatalf("the answer is not {mfa_required, delivery}: %s", strings.TrimSpace(raw))
	}
	for _, secret := range []string{code, "5309", "867", "mfa-user", "auth", "3"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("the delivery answer discloses %q: %s", secret, strings.TrimSpace(raw))
		}
	}
}

// TestMfaDeliveryRefusesAJunkChallengeAndSpendsNoGuess pins the two properties that make polling it
// safe. A bearer it will not accept gets the SAME sentence the verify path gives, so the route is no
// oracle for which challenge ids are live; and because no code is submitted, no number of polls can
// move the guess counter a lockout is built on.
func TestMfaDeliveryRefusesAJunkChallengeAndSpendsNoGuess(t *testing.T) {
	server, _ := newStockServer(t)
	token, challengeID := mfaChallengeInFlight(t, server)

	status, answer, raw := deliveryState(t, server, "not-a-token")
	if status != 401 {
		t.Fatalf("a junk challenge answered %d, want 401", status)
	}
	detail, _ := answer["detail"].(string)
	if !strings.Contains(detail+raw, "Invalid or expired challenge") {
		t.Fatalf("the refusal is not the verify path's sentence: %s", strings.TrimSpace(raw))
	}

	before := challengeRecord(t, server, challengeID).Attempts
	for i := 0; i < 20; i++ {
		if status, _, _ := deliveryState(t, server, token); status != 200 {
			t.Fatalf("poll %d answered %d", i, status)
		}
	}
	if after := challengeRecord(t, server, challengeID).Attempts; after != before {
		t.Fatalf("twenty polls moved the guess counter from %d to %d: a client that polls locks itself out", before, after)
	}
}
