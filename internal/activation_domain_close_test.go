// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"strings"
	"testing"
)

func TestDomainCloseRetainedKeyCapDuplicatesAndIdempotence(t *testing.T) {
	f := domainTestConfigured(t)
	d, _ := f.server.domainEngine()
	d.config.MaxLeases = 2 // Explicit synthetic retained closed-key cap, not production policy.
	scope := DomainScope{f.config.Scopes[0].Binding.AccountID, "manifest"}
	first := DomainGateKey{"external-human", "first-session", scope}
	second := DomainGateKey{"external-human", "second-session", scope}
	close := domainCloseTestControl(f, d.epoch, []DomainGateKey{first, first, second})
	result, err := f.server.DomainControl(context.Background(), close)
	if err != nil || !result.Value.(map[string]bool)["drained"] || len(d.closed) != 2 {
		t.Fatal("duplicate tuples incorrectly consume capacity", err)
	}
	close.Keys = []DomainGateKey{first, second, first}
	if _, err = f.server.DomainControl(context.Background(), close); err != nil {
		t.Fatal("known closures are not idempotent at capacity", err)
	}
	third := DomainGateKey{"external-human", "third-session", scope}
	close.Keys = []DomainGateKey{first, third, third}
	if _, err = f.server.DomainControl(context.Background(), close); err == nil || len(d.closed) != 2 || d.closed[third] {
		t.Fatal("retained closed-key cap failed or refusal partially inserted")
	}
}
func TestDomainCloseBatchRefusesIdentifiersAndCapacityAtomically(t *testing.T) {
	f := domainTestConfigured(t)
	d, _ := f.server.domainEngine()
	d.config.MaxLeases = 2
	owned := f.config.Scopes[0]
	scope := DomainScope{owned.Binding.AccountID, "manifest"}
	first := DomainGateKey{"external-human", "first", scope}
	oversized := strings.Repeat("x", owned.Bounds.MaxIdentifierBytes+1)
	batches := [][]DomainGateKey{
		{first, {oversized, "session", scope}},
		{first, {"external-human", oversized, scope}},
		{first, {"external-human", "session", DomainScope{"unknown-account", "manifest"}}},
		{first, {"external-human", "second", scope}, {"external-human", "third", scope}},
	}
	for _, keys := range batches {
		close := domainCloseTestControl(f, d.epoch, keys)
		if _, err := f.server.DomainControl(context.Background(), close); err == nil || len(d.closed) != 0 {
			t.Fatal("invalid closure batch partially consumed retained map")
		}
	}
}
func domainCloseTestControl(f *domainTestFixture, epoch string, keys []DomainGateKey) DomainControl {
	return DomainControl{Action: "close", Epoch: epoch, HostID: f.config.HostID, ChannelToken: f.config.OwnerControlToken, Keys: keys}
}
