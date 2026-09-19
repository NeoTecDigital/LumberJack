// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// GIVING UP ON A CODE IS A FACT ABOUT THE LOGIN, and until this file it was not recorded anywhere.
// The forward-dispatcher's give-up path called operation="outbound_ack" — the DELIVERED op — so a
// code that never left the building was cleared by the same call that clears one the carrier took,
// and the challenge was left looking exactly like a challenge whose code is on somebody's phone.
// The person waiting could not be told the difference, and neither could an operator.
//
// The pair below is what makes the difference durable. The outbound ITEM is still deleted in both
// cases — it holds the plaintext code, and an item nothing will send again is only a code sitting in
// the state file — so what changes is not the delete but the RECORD left behind on the challenge:
//
//	outbound_ack {id, outcome:"sent"}    -> MFAChallenge.Delivery = "sent"
//	outbound_failed {id, error_class, attempts} -> Delivery = "failed", DeliveryError, DeliveryTries
//
// outcome:"expired" records NOTHING, because an expired item's challenge is expired too and calling
// that a delivery would be a lie the poll would then repeat to the user.

// challengeRecord reads one challenge off the forest under the shared hold, so an assertion about
// delivery state is an assertion about what was PERSISTED and not about a return value.
func challengeRecord(t *testing.T, server *Server, id string) core.MFAChallenge {
	t.Helper()
	var record core.MFAChallenge
	found := false
	server.readForest(func() {
		record, found = server.forest.MFAChallenges[id]
	})
	if !found {
		t.Fatalf("no challenge %s on the forest", id)
	}
	return record
}

// seedChallenge plants a live challenge and the outbound item a login would have enqueued beside it,
// keyed the way beginMFAChallenge keys them: one id names both.
func seedChallenge(t *testing.T, server *Server, id, userID string) {
	t.Helper()
	now := time.Now().Unix()
	if err := server.changeForest(func() error {
		if server.forest.MFAChallenges == nil {
			server.forest.MFAChallenges = map[string]core.MFAChallenge{}
		}
		server.forest.MFAChallenges[id] = core.MFAChallenge{
			UserID: userID, CodeHash: server.mfaCodeHash("000000"),
			CreatedAt: now, ExpiresAt: now + 300,
		}
		state := server.correspondenceState()
		if state.Outbound == nil {
			state.Outbound = map[string]core.OutboundMessage{}
		}
		state.Outbound[id] = core.OutboundMessage{
			ID: id, Channel: "sms", Purpose: "mfa", To: "+15550000000",
			Payload: "000000", ChallengeID: id, UserID: userID,
			CreatedAt: now, ExpiresAt: now + 300,
		}
		return nil
	}); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
}

// TestHubOutboundFailedRecordsTerminalStateOnTheChallenge is the whole point of the op: the give-up
// stops being a silent delete. The item goes, the challenge keeps the verdict, and the failure class
// and attempt count are kept BESIDE it so an operator reading the state file can tell an unconfigured
// provider from a carrier having a bad afternoon.
//
// The first red this file ever printed was a BUILD failure — `record.Delivery undefined (type
// core.MFAChallenge has no field or method Delivery)`, eleven lines of it — because the verdict had
// nowhere to live. The fields were added inert (they are data; they assert nothing on their own) and
// the suite run again, which is the red worth keeping: the store can hold the verdict and no op
// writes one.
//
// OBSERVED RED (the four delivery fields on core.MFAChallenge with nothing writing them; the
// ApplicationHub served pending/status/deliver/outbound/outbound_ack and no outbound_failed, so the
// op fell to the default — `go test ./internal -run
// 'TestHubOutboundFailed|TestHubOutboundAckRecordsDelivered|TestResendClearsATerminalDeliveryMark'
// -count=1`):
//
//	--- FAIL: TestHubOutboundFailedRecordsTerminalStateOnTheChallenge (0.04s)
//	    application_hub_delivery_test.go:89: ApplicationHub(operation=outbound_failed) refused: unknown hub operation
//	--- FAIL: TestHubOutboundFailedOfAnAbsentIDIsANoOp (0.04s)
//	    application_hub_delivery_test.go:133: ApplicationHub(operation=outbound_failed) refused: unknown hub operation
//	FAIL
func TestHubOutboundFailedRecordsTerminalStateOnTheChallenge(t *testing.T) {
	server, _ := newStockServer(t)
	seedChallenge(t, server, "chal-failed", "user-1")

	out := hubOut(t, server, map[string]interface{}{
		"operation": "outbound_failed", "id": "chal-failed",
		"error_class": "auth", "attempts": 1,
	})
	var answer map[string]interface{}
	if err := json.Unmarshal(out, &answer); err != nil {
		t.Fatalf("outbound_failed did not return an object: %v (%s)", err, out)
	}
	if recorded, _ := answer["recorded"].(bool); !recorded {
		t.Fatalf("outbound_failed of a live challenge did not report recorded:true: %s", out)
	}

	record := challengeRecord(t, server, "chal-failed")
	if record.Delivery != "failed" {
		t.Fatalf("the challenge records delivery %q, want \"failed\": a give-up the user cannot be told about", record.Delivery)
	}
	if record.DeliveryError != "auth" {
		t.Fatalf("the failure class was not kept: %q", record.DeliveryError)
	}
	if record.DeliveryTries != 1 {
		t.Fatalf("the attempt count was not kept: %d", record.DeliveryTries)
	}
	if record.DeliveryAt == 0 {
		t.Fatal("the give-up was recorded with no time, so nobody can tell a fresh failure from a stale one")
	}
	// The code itself must not survive the give-up: the item is the one place it exists in the clear.
	server.readForest(func() {
		if _, still := server.forest.Correspondence.Outbound["chal-failed"]; still {
			t.Fatal("the given-up item survived on the outbox: a plaintext code left in the state file")
		}
	})
	// And the challenge is NOT destroyed — the user must still be able to ask for another code.
	if record.CodeHash == "" {
		t.Fatal("the challenge was gutted; a resend has nothing left to swap a code into")
	}
}

// TestHubOutboundFailedOfAnAbsentIDIsANoOp keeps the miss convention the outbound pair already has:
// deliver answers {"delivered": false} and outbound_ack answers {"acked": false} rather than
// erroring, so a give-up racing an ack that already cleared the id is benign here too.
func TestHubOutboundFailedOfAnAbsentIDIsANoOp(t *testing.T) {
	server, _ := newStockServer(t)
	seedChallenge(t, server, "present", "user-1")

	out := hubOut(t, server, map[string]interface{}{
		"operation": "outbound_failed", "id": "ghost", "error_class": "timeout", "attempts": 7,
	})
	var answer map[string]interface{}
	if err := json.Unmarshal(out, &answer); err != nil {
		t.Fatalf("outbound_failed did not return an object: %v (%s)", err, out)
	}
	if recorded, ok := answer["recorded"].(bool); !ok || recorded {
		t.Fatalf("an absent id should report recorded:false like the ack's miss, got %s", out)
	}
	if record := challengeRecord(t, server, "present"); record.Delivery != "" {
		t.Fatalf("a miss marked an unrelated challenge %q", record.Delivery)
	}
	server.readForest(func() {
		if _, ok := server.forest.Correspondence.Outbound["present"]; !ok {
			t.Fatal("a no-op give-up disturbed the queue")
		}
	})
}

// TestHubOutboundAckRecordsDeliveredButNotExpired is the other side of the same distinction. A
// delivered item marks its challenge "sent", which is what lets a waiting client stop asking. An
// EXPIRED item is swept through the same op and must mark nothing: its challenge died with it, and
// "sent" on a dead challenge would be a delivery that never happened.
//
// OBSERVED RED (outbound_ack took only an id and wrote nothing to MFAChallenges, so a delivered code
// left the challenge indistinguishable from one still in the queue — same run as above):
//
//	--- FAIL: TestHubOutboundAckRecordsDeliveredButNotExpired (0.11s)
//	    --- FAIL: TestHubOutboundAckRecordsDeliveredButNotExpired/a_delivered_item_marks_its_challenge_sent (0.04s)
//	        application_hub_delivery_test.go:175: the challenge records delivery "", want "sent"
//	    --- FAIL: TestHubOutboundAckRecordsDeliveredButNotExpired/an_omitted_outcome_still_means_delivered,_so_the_existing_caller_is_unchanged (0.04s)
//	        application_hub_delivery_test.go:185: a bare ack recorded "", want "sent"
//	FAIL
func TestHubOutboundAckRecordsDeliveredButNotExpired(t *testing.T) {
	t.Run("a delivered item marks its challenge sent", func(t *testing.T) {
		server, _ := newStockServer(t)
		seedChallenge(t, server, "chal-sent", "user-1")

		hubOut(t, server, map[string]interface{}{
			"operation": "outbound_ack", "id": "chal-sent", "outcome": "sent",
		})
		if record := challengeRecord(t, server, "chal-sent"); record.Delivery != "sent" {
			t.Fatalf("the challenge records delivery %q, want \"sent\"", record.Delivery)
		}
	})

	t.Run("an omitted outcome still means delivered, so the existing caller is unchanged", func(t *testing.T) {
		server, _ := newStockServer(t)
		seedChallenge(t, server, "chal-default", "user-1")

		hubOut(t, server, map[string]interface{}{"operation": "outbound_ack", "id": "chal-default"})
		if record := challengeRecord(t, server, "chal-default"); record.Delivery != "sent" {
			t.Fatalf("a bare ack recorded %q, want \"sent\"", record.Delivery)
		}
	})

	t.Run("an expired sweep records nothing", func(t *testing.T) {
		server, _ := newStockServer(t)
		seedChallenge(t, server, "chal-expired", "user-1")

		hubOut(t, server, map[string]interface{}{
			"operation": "outbound_ack", "id": "chal-expired", "outcome": "expired",
		})
		if record := challengeRecord(t, server, "chal-expired"); record.Delivery != "" {
			t.Fatalf("an expiry sweep claimed delivery %q; nothing was sent", record.Delivery)
		}
	})
}

// TestResendClearsATerminalDeliveryMark closes the loop the sign-in UI depends on. Once a challenge
// reads "failed" the client shows it and offers a resend — and if the resend left the mark in place
// the very next poll would report the OLD failure, so the button would look broken every time it
// worked. /mfa/start swaps a fresh code in; the delivery verdict belongs to that new code, not the
// one that never left.
//
// OBSERVED RED (same run as above; there was no outbound_failed to mark the challenge with, so the
// case could not even reach the clear it asserts):
//
//	--- FAIL: TestResendClearsATerminalDeliveryMark (0.11s)
//	    application_hub_delivery_test.go:227: ApplicationHub(operation=outbound_failed) refused: unknown hub operation
//	FAIL
//
// OBSERVED RED AGAIN once the op existed and only the clear was missing (resendMFAChallenge swapped
// the code and left Delivery/DeliveryError where they were):
//
//	--- FAIL: TestResendClearsATerminalDeliveryMark (0.11s)
//	    application_hub_delivery_test.go:255: after a resend the challenge still reads delivery "failed" (class "auth"): the next poll reports a failure that belongs to the previous code
//	FAIL
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.307s
func TestResendClearsATerminalDeliveryMark(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	body := login(t, server, map[string]interface{}{
		"username": user.Username, "password": "securepass123", "phone_last4": "5309",
	})
	if body.status != 200 {
		t.Fatalf("MFA login answered %d, want 200", body.status)
	}
	token := body.json["challenge"].(string)
	challengeID := challengeIDOf(t, server, token)

	hubOut(t, server, map[string]interface{}{
		"operation": "outbound_failed", "id": challengeID, "error_class": "auth", "attempts": 1,
	})
	if record := challengeRecord(t, server, challengeID); record.Delivery != "failed" {
		t.Fatalf("the give-up did not land, so this case cannot prove the clear: %q", record.Delivery)
	}

	if err := server.resendMFAChallenge(token); err != nil {
		t.Fatalf("resend refused: %v", err)
	}
	record := challengeRecord(t, server, challengeID)
	if record.Delivery != "" || record.DeliveryError != "" || record.DeliveryTries != 0 {
		t.Fatalf("after a resend the challenge still reads delivery %q (class %q): the next poll reports a failure that belongs to the previous code",
			record.Delivery, record.DeliveryError)
	}
	// And the resend really did queue a new code to judge.
	server.readForest(func() {
		if _, ok := server.forest.Correspondence.Outbound[challengeID]; !ok {
			t.Fatal("the resend cleared the mark without queueing anything")
		}
	})
}
