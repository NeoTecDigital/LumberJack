package internal

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// The outbound pair on the trusted ApplicationHub: the read that lists the external outbox
// oldest-first under a cap, and the durable ack that clears one item. They mirror the
// pending/deliver pair over CorrespondenceState.Pending, one layer over CorrespondenceState.Outbound,
// and they are the contract the Julia forward-dispatcher (drainOutbound! in HubRuntime.jl) reaches
// for. Each op is proven red against the bare pending/status/deliver hub before it is added.

// hubOut drives the trusted ApplicationHub boundary the way Corresponder does — a JSON request in, a
// JSON document out — and fails the test on a transport-level refusal, so a missing op reads as the
// red it is rather than a silently empty answer.
func hubOut(t *testing.T, server *Server, request map[string]interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal hub request: %v", err)
	}
	out, err := server.ApplicationHub(raw)
	if err != nil {
		t.Fatalf("ApplicationHub(operation=%v) refused: %v", request["operation"], err)
	}
	return out
}

// outboundItem is one queued external message with a chosen id and creation time, so a test controls
// queue order and size directly. Its fields carry the routing markers the dispatcher selects on.
//
// CreatedAt is whatever the caller asks for — it is the sort key, and these tests use small numbers
// to make an order readable. ExpiresAt is NOT derived from it: the window is anchored to the real
// clock, because operation="outbound" now filters and sweeps expired items, and `createdAt + 300`
// with createdAt=100 is a window that closed in 1970. A fixture that was never meant to be expired
// should not become one the moment expiry starts being enforced.
func outboundItem(id string, createdAt int64) core.OutboundMessage {
	return core.OutboundMessage{
		ID: id, Channel: "sms", Purpose: "mfa", To: "+15550000000",
		Payload: "000000", ChallengeID: id, CreatedAt: createdAt, ExpiresAt: time.Now().Unix() + 300,
	}
}

// seedOutbound plants items on the external outbox in ONE durable change, so a test needs no login per
// item and the plant lands exactly where the ops read.
func seedOutbound(t *testing.T, server *Server, items ...core.OutboundMessage) {
	t.Helper()
	if err := server.changeForest(func() error {
		state := server.correspondenceState()
		if state.Outbound == nil {
			state.Outbound = map[string]core.OutboundMessage{}
		}
		for _, item := range items {
			state.Outbound[item.ID] = item
		}
		return nil
	}); err != nil {
		t.Fatalf("seed outbound: %v", err)
	}
}

// listOutbound calls operation="outbound" and decodes the []OutboundMessage the dispatcher iterates.
func listOutbound(t *testing.T, server *Server) []core.OutboundMessage {
	t.Helper()
	out := hubOut(t, server, map[string]interface{}{"operation": "outbound"})
	var items []core.OutboundMessage
	if err := json.Unmarshal(out, &items); err != nil {
		t.Fatalf("outbound did not return a list: %v (%s)", err, out)
	}
	return items
}

func outboundIDList(items []core.OutboundMessage) []string {
	ids := make([]string, len(items))
	for i, item := range items {
		ids[i] = item.ID
	}
	return ids
}

// TestHubOutboundListsOldestFirstAndCaps is the read half: operation="outbound" returns the queued
// items sorted by CreatedAt ascending (the dispatcher forwards the oldest first), and at most 128 of
// them, exactly as operation="pending" caps its own list.
//
// OBSERVED RED (the ApplicationHub served only pending/status/deliver, so operation="outbound" fell
// to the default and returned an error, `go test ./internal -run TestHubOutboundListsOldestFirstAndCaps -count=1`):
//
//	--- FAIL: TestHubOutboundListsOldestFirstAndCaps (0.08s)
//	    --- FAIL: TestHubOutboundListsOldestFirstAndCaps/oldest-first_regardless_of_insertion_order (0.04s)
//	        application_hub_outbound_test.go:95: ApplicationHub(operation=outbound) refused: unknown hub operation
//	    --- FAIL: TestHubOutboundListsOldestFirstAndCaps/caps_at_the_128_oldest,_in_order (0.04s)
//	        application_hub_outbound_test.go:109: ApplicationHub(operation=outbound) refused: unknown hub operation
//	FAIL
func TestHubOutboundListsOldestFirstAndCaps(t *testing.T) {
	t.Run("oldest-first regardless of insertion order", func(t *testing.T) {
		server, _ := newStockServer(t)
		seedOutbound(t, server, outboundItem("c", 300), outboundItem("a", 100), outboundItem("b", 200))

		got := listOutbound(t, server)
		if ids := outboundIDList(got); len(ids) != 3 || ids[0] != "a" || ids[1] != "b" || ids[2] != "c" {
			t.Fatalf("outbound is not oldest-first: %v", ids)
		}
	})

	t.Run("caps at the 128 oldest, in order", func(t *testing.T) {
		server, _ := newStockServer(t)
		batch := make([]core.OutboundMessage, 0, 130)
		for i := 0; i < 130; i++ {
			batch = append(batch, outboundItem(fmt.Sprintf("item-%03d", i), int64(1000+i)))
		}
		seedOutbound(t, server, batch...)

		got := listOutbound(t, server)
		if len(got) != 128 {
			t.Fatalf("outbound returned %d items, want the 128 cap", len(got))
		}
		if got[0].ID != "item-000" || got[127].ID != "item-127" {
			t.Fatalf("the cap did not keep the oldest 128 in order: first=%s last=%s", got[0].ID, got[127].ID)
		}
	})
}

// TestHubOutboundAckDeletesNamedIDDurably is the ack half: operation="outbound_ack" with an id deletes
// exactly that item under changeForest — the delete lands on the forest, not just the answer — and
// leaves every other item in place, exactly as operation="deliver" clears one pending record.
//
// OBSERVED RED (the ApplicationHub served no outbound_ack, so the op fell to the default and returned
// an error, `go test ./internal -run TestHubOutboundAckDeletesNamedIDDurably -count=1`):
//
//	--- FAIL: TestHubOutboundAckDeletesNamedIDDurably (0.04s)
//	    application_hub_outbound_test.go:133: ApplicationHub(operation=outbound_ack) refused: unknown hub operation
//	FAIL
func TestHubOutboundAckDeletesNamedIDDurably(t *testing.T) {
	server, _ := newStockServer(t)
	seedOutbound(t, server, outboundItem("keep", 100), outboundItem("drop", 200))

	out := hubOut(t, server, map[string]interface{}{"operation": "outbound_ack", "id": "drop"})
	var ack map[string]interface{}
	if err := json.Unmarshal(out, &ack); err != nil {
		t.Fatalf("outbound_ack did not return an object: %v (%s)", err, out)
	}
	if acked, _ := ack["acked"].(bool); !acked {
		t.Fatalf("outbound_ack of a live id did not report acked:true: %s", out)
	}

	server.readForest(func() {
		if _, ok := server.forest.Correspondence.Outbound["drop"]; ok {
			t.Fatal("the acked item survived on the outbox: the delete did not land under changeForest")
		}
		if _, ok := server.forest.Correspondence.Outbound["keep"]; !ok {
			t.Fatal("outbound_ack removed an id it was not named")
		}
	})
}

// TestHubOutboundAckOfAbsentIDIsANoOp pins the Pending-pair convention for a miss: operation="deliver"
// answers {"delivered": false} for an id it cannot find rather than erroring, so operation="outbound_ack"
// answers {"acked": false} and disturbs nothing. A drained item already cleared by a racing retry must
// not turn the ack into a failure.
//
// OBSERVED RED (the ApplicationHub served no outbound_ack, so the op fell to the default and returned
// an error, `go test ./internal -run TestHubOutboundAckOfAbsentIDIsANoOp -count=1`):
//
//	--- FAIL: TestHubOutboundAckOfAbsentIDIsANoOp (0.04s)
//	    application_hub_outbound_test.go:167: ApplicationHub(operation=outbound_ack) refused: unknown hub operation
//	FAIL
func TestHubOutboundAckOfAbsentIDIsANoOp(t *testing.T) {
	server, _ := newStockServer(t)
	seedOutbound(t, server, outboundItem("present", 100))

	out := hubOut(t, server, map[string]interface{}{"operation": "outbound_ack", "id": "ghost"})
	var ack map[string]interface{}
	if err := json.Unmarshal(out, &ack); err != nil {
		t.Fatalf("outbound_ack did not return an object: %v (%s)", err, out)
	}
	if acked, ok := ack["acked"].(bool); !ok || acked {
		t.Fatalf("an absent id should report acked:false like deliver's miss, got %s", out)
	}

	server.readForest(func() {
		if _, ok := server.forest.Correspondence.Outbound["present"]; !ok {
			t.Fatal("a no-op ack disturbed the queue")
		}
	})
}

// TestHubOutboundFullPathLoginToAck is the engine side of the whole send path in one process: a real
// MFA login enqueues one external item (Track B), operation="outbound" lists it exactly as the
// dispatcher would (Track C), operation="outbound_ack" clears it, and the outbox is empty afterward.
// It proves the two ops read and clear precisely what beginMFAChallenge enqueues, with no seam faked.
//
// OBSERVED RED (before the ops existed, operation="outbound" refused with "unknown hub operation",
// `go test ./internal -run TestHubOutboundFullPathLoginToAck -count=1`):
//
//	--- FAIL: TestHubOutboundFullPathLoginToAck (0.12s)
//	    application_hub_outbound_test.go:207: ApplicationHub(operation=outbound) refused: unknown hub operation
//	FAIL
func TestHubOutboundFullPathLoginToAck(t *testing.T) {
	server, _ := newStockServer(t)
	user := addMFAUser(t, server)

	body := login(t, server, map[string]interface{}{
		"username": user.Username, "password": "securepass123", "phone_last4": "5309",
	})
	if body.status != 200 {
		t.Fatalf("MFA login answered %d, want 200", body.status)
	}
	challengeID := challengeIDOf(t, server, body.json["challenge"].(string))
	enqueued := outboundFor(t, server, challengeID)

	listed := listOutbound(t, server)
	if len(listed) != 1 || listed[0].ID != challengeID {
		t.Fatalf("outbound did not list the enqueued item: %v", outboundIDList(listed))
	}
	if listed[0].Payload != enqueued.Payload || listed[0].To != user.Phone || listed[0].Purpose != "mfa" {
		t.Fatalf("the listed item is not the enqueued code: %+v", listed[0])
	}

	ack := hubOut(t, server, map[string]interface{}{"operation": "outbound_ack", "id": challengeID})
	var result map[string]interface{}
	if err := json.Unmarshal(ack, &result); err != nil || result["acked"] != true {
		t.Fatalf("outbound_ack did not clear the delivered item: %s", ack)
	}
	if remaining := listOutbound(t, server); len(remaining) != 0 {
		t.Fatalf("the outbox is not empty after ack: %v", outboundIDList(remaining))
	}
}
