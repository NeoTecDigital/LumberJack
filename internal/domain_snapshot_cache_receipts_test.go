// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "testing"

func TestDomainSnapshotCacheDecodesRetainedReceiptsFreshForEveryView(t *testing.T) {
	x := evaluationFixture(t, "command")
	x.f.server.forestMutex.Lock()
	root, err := x.f.server.forest.GetNode(x.entry.owned.Binding.RootID)
	if err != nil {
		x.f.server.forestMutex.Unlock()
		t.Fatal(err)
	}
	// Structured decoder-isolation input only, not a claimed durable native pair.
	root.CommandReceipts["receipt-isolation-input"] = stagedReceipt{Version: 1,
		Command: stagedCommand{CommandID: "decoder-only", Action: "png.store.write.define"},
		Targets: []stagedTarget{{NodeID: "record-a", Kind: "synthetic-record", Fields: []string{"label"}}}}
	x.f.server.forestMutex.Unlock()
	x.f.server.forestMutex.RLock()
	defer x.f.server.forestMutex.RUnlock()
	first, err := x.f.server.domainViewLocked(x.entry.owned)
	if err != nil {
		t.Fatal(err)
	}
	first.RetainedReceipts["decoder-only"].Receipt.Targets[0].Fields[0] = "callback-poison"
	delete(first.RetainedReceipts, "decoder-only")
	second, err := x.f.server.domainViewLocked(x.entry.owned)
	if err != nil {
		t.Fatal(err)
	}
	if second.RetainedReceipts["decoder-only"].Receipt.Targets[0].Fields[0] != "label" {
		t.Fatal("a callback poisoned cached or live retained receipt metadata")
	}
}
