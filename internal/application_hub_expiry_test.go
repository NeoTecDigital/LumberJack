package internal

import (
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// WHAT AN UNEXPIRED OUTBOX IS. Every item on it is a plaintext second-factor code — the one place
// in the system where one exists — addressed to a phone number. The challenge it belongs to dies in
// five minutes, so a minute later the item can do nothing but sit in the state file being readable,
// and an unacked one sat there FOREVER: a dispatcher that died mid-drain, a carrier that refused, a
// process restarted at the wrong moment, and the code stayed on disk indefinitely with a phone
// number beside it.
//
// The read filters and the store is swept, and both halves are needed. The filter is what makes a
// dispatcher unable to deliver a code whose challenge has already died — a text that arrives for a
// login nobody can complete is worse than no text. The sweep is what keeps the file from growing a
// permanent archive of codes and numbers that the filter would merely hide.

// expiredOutboundItem is a queued message whose window has already closed — the state a dispatcher
// crash or a carrier refusal leaves behind.
func expiredOutboundItem(id string, expiredAgo time.Duration) core.OutboundMessage {
	expiry := time.Now().Add(-expiredAgo).Unix()
	return core.OutboundMessage{
		ID: id, Channel: "sms", Purpose: "mfa", To: "+15550000000",
		Payload: "000000", ChallengeID: id, CreatedAt: expiry - 300, ExpiresAt: expiry,
	}
}

// outboundStoreIDs reads the outbox as it actually IS, under the read hold, rather than as the hub
// op reports it — which is the difference between "hidden" and "gone".
func outboundStoreIDs(t *testing.T, server *Server) []string {
	t.Helper()
	ids := []string{}
	server.readForest(func() {
		if server.forest.Correspondence == nil {
			return
		}
		for id := range server.forest.Correspondence.Outbound {
			ids = append(ids, id)
		}
	})
	return ids
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestOutboundHidesAndSweepsAnExpiredItem is both halves at once: the dispatcher is never handed an
// item whose window has closed, and the item is GONE from the store afterwards — not merely filtered
// out of one answer while the code stays on disk.
//
// OBSERVED RED (before the filter and the sweep existed,
// `go test ./internal -run TestOutbound -count=1`):
//
//	--- FAIL: TestOutboundHidesAndSweepsAnExpiredItem (0.04s)
//	    application_hub_expiry_test.go:76: outbound handed the dispatcher an expired item: [dead-one]
//	    application_hub_expiry_test.go:79: the expired item is still in the store after a poll: [dead-one]
//	--- FAIL: TestOutboundLeavesLiveItemsAlone (0.04s)
//	    application_hub_expiry_test.go:97: outbound listed [dead-two still-live], want only the live item
//	FAIL	github.com/NeoTecDigital/LumberJack/internal	0.116s
func TestOutboundHidesAndSweepsAnExpiredItem(t *testing.T) {
	server, _ := newStockServer(t)
	seedOutbound(t, server, expiredOutboundItem("dead-one", time.Minute))

	listed := listOutbound(t, server)
	if len(listed) != 0 {
		t.Errorf("outbound handed the dispatcher an expired item: %v", outboundIDList(listed))
	}
	if ids := outboundStoreIDs(t, server); contains(ids, "dead-one") {
		t.Errorf("the expired item is still in the store after a poll: %v", ids)
	}
}

// TestOutboundLeavesLiveItemsAlone. The sweep is scoped by the clock and nothing else: an item still
// inside its window is listed and kept, so a drain that races the sweep cannot lose a code that was
// about to be delivered.
//
// OBSERVED RED (before the filter and the sweep existed, same run):
//
//	--- FAIL: TestOutboundLeavesLiveItemsAlone (0.04s)
//	    application_hub_expiry_test.go:97: outbound listed [dead-two still-live], want only the live item
//
// Its other assertions are the fix's opposite edge: what stops "sweep expired" becoming "clear the
// outbox".
func TestOutboundLeavesLiveItemsAlone(t *testing.T) {
	server, _ := newStockServer(t)
	live := outboundItem("still-live", time.Now().Unix())
	seedOutbound(t, server, live, expiredOutboundItem("dead-two", time.Hour))

	listed := listOutbound(t, server)
	if len(listed) != 1 || listed[0].ID != "still-live" {
		t.Fatalf("outbound listed %v, want only the live item", outboundIDList(listed))
	}
	if listed[0].Payload != live.Payload || listed[0].To != live.To {
		t.Errorf("the live item came back altered: %+v", listed[0])
	}
	ids := outboundStoreIDs(t, server)
	if !contains(ids, "still-live") {
		t.Errorf("the sweep took a live item: %v", ids)
	}
	if contains(ids, "dead-two") {
		t.Errorf("the expired item survived the sweep: %v", ids)
	}
}

// TestOutboundSweepOutlivesTheProcess. The sweep is a durable change, not an in-memory filter, so a
// code removed from the outbox is removed from the STATE FILE — which is the artifact that actually
// leaks. A sweep that only edited memory would be undone by the next restart.
//
// OBSERVED RED (before the sweep existed, same run):
//
//	--- FAIL: TestOutboundSweepOutlivesTheProcess (0.04s)
//	    application_hub_expiry_test.go:132: the expired code is back after a reload: [dead-three]
func TestOutboundSweepOutlivesTheProcess(t *testing.T) {
	server, dir := newStockServer(t)
	seedOutbound(t, server, expiredOutboundItem("dead-three", time.Minute))
	listOutbound(t, server)

	loaded, err := LoadServer(types.ServerConfig{
		Process: types.ProcessInfo{ID: "stock_process", Name: "stock", LogPath: dir, DatabasePath: dir},
	})
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if ids := outboundStoreIDs(t, loaded); contains(ids, "dead-three") {
		t.Errorf("the expired code is back after a reload: %v", ids)
	}
}
