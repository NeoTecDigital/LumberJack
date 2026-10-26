// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"errors"
	"testing"
)

type receiptProjectionProduct struct {
	domainTestProduct
	include bool
	err     error
}

func (p receiptProjectionProduct) IncludeRetainedReceipts(DomainInput) (bool, error) {
	return p.include, p.err
}

func receiptProjectionFixture(t *testing.T) evaluationTestFixture {
	t.Helper()
	x := evaluationFixture(t, "read")
	x.f.server.forestMutex.Lock()
	root, err := x.f.server.forest.GetNode(x.entry.owned.Binding.RootID)
	if err == nil {
		root.CommandReceipts["projection-input"] = stagedReceipt{Version: 1,
			Command: stagedCommand{CommandID: "history-only", Action: "png.store.write.define"},
			Targets: []stagedTarget{{NodeID: "record-a", Kind: "synthetic-record", Fields: []string{"label"}}}}
	}
	x.f.server.forestMutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestDomainReceiptProjectionDefaultAndExplicitHistoryAreFresh(t *testing.T) {
	x := receiptProjectionFixture(t)
	x.f.server.forestMutex.RLock()
	defer x.f.server.forestMutex.RUnlock()
	for _, product := range []DomainProduct{domainTestProduct{}, receiptProjectionProduct{include: true}} {
		view, err := x.f.server.domainInputViewLocked(product, x.entry.input, x.entry.owned)
		if _, present := view.RetainedReceipts["history-only"]; err != nil || !present {
			t.Fatalf("historical projection omitted: %v", err)
		}
		delete(view.RetainedReceipts, "history-only")
	}
}

func TestDomainReceiptProjectionOrdinaryViewKeepsCurrentRecordsAndRevision(t *testing.T) {
	x := receiptProjectionFixture(t)
	x.f.server.forestMutex.RLock()
	defer x.f.server.forestMutex.RUnlock()
	view, err := x.f.server.domainInputViewLocked(receiptProjectionProduct{}, x.entry.input, x.entry.owned)
	if err != nil || view.RetainedReceipts != nil || len(view.Records) == 0 || view.Revision == "" {
		t.Fatalf("ordinary current view invalid: %v", err)
	}
	x.d.products["manifest"] = receiptProjectionProduct{}
	intent, owned, _, err := x.f.server.resolveDomainLocked(x.d, x.entry.input)
	if err != nil || owned.Binding != x.entry.owned.Binding || !domainEqual(intent, x.entry.intent) {
		t.Fatal("selector changed current resolve/intent", err)
	}
}

func TestDomainReceiptProjectionSelectorErrorDenies(t *testing.T) {
	x := receiptProjectionFixture(t)
	x.f.server.forestMutex.RLock()
	defer x.f.server.forestMutex.RUnlock()
	want := errors.New("invalid historical projection input")
	view, err := x.f.server.domainInputViewLocked(receiptProjectionProduct{err: want}, x.entry.input, x.entry.owned)
	if !errors.Is(err, want) || view.Records != nil {
		t.Fatal("selector failure did not fail closed")
	}
}

func TestDomainReceiptProjectionHistoricalDecodeStillFailsClosed(t *testing.T) {
	x := receiptProjectionFixture(t)
	x.f.server.forestMutex.Lock()
	root, _ := x.f.server.forest.GetNode(x.entry.owned.Binding.RootID)
	root.CommandReceipts["invalid-history"] = "not a retained receipt"
	x.f.server.forestMutex.Unlock()
	x.f.server.forestMutex.RLock()
	defer x.f.server.forestMutex.RUnlock()
	if _, err := x.f.server.domainInputViewLocked(receiptProjectionProduct{include: true}, x.entry.input, x.entry.owned); err == nil {
		t.Fatal("historical decode corruption accepted")
	}
}
