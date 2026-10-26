// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"testing"
)

func TestPersonalSourceRealPairDistinctLeasesAndFreshDisclosure(t *testing.T) {
	f := sourceUnitFixtureNew(t)
	e, _, admitted := sourceUnitCommitted(t, f)
	if admitted.LeaseRef.LeaseID == admitted.ExecutionLease.LeaseID || e.phases["disclosure"].LeaseID == admitted.ExecutionLease.LeaseID || e.durable == nil {
		t.Fatal("fabricated/cast phase lease or pair missing")
	}
	if f.server.forest.Children[e.candidate.RootID] == nil || f.server.forest.PersonalBindings == nil {
		t.Fatal("actual roots/ledger not published")
	}
	disk := stagedTestDisk(t, f.server)
	if disk.PersonalBindings == nil || disk.Children[e.candidate.RootID] == nil {
		t.Fatal("ledger/root not in same stored snapshot")
	}
	_, err := f.p.disclosePersonal(context.Background(), sourceUnitRequest(f, "provision.disclose", sourcePersonalDisclose{e.phases["disclosure"], "unit_disclosure_proof"}))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.revoked = true
	f.mu.Unlock()
	if _, err = f.p.disclosePersonal(context.Background(), sourceUnitRequest(f, "provision.disclose", sourcePersonalDisclose{e.phases["disclosure"], "unit_revoked_proof"})); err == nil {
		t.Fatal("current Core revocation ignored")
	}
	if _, err = f.p.leaseRelease(context.Background(), sourceUnitRequest(f, "lease.release", sourceLeaseRelease{admitted.LeaseRef, "released"})); err != nil {
		t.Fatal(err)
	}
}
func TestPersonalSourceRestartSameCommandPreservesIDsAndUnknownBags(t *testing.T) {
	f := sourceUnitFixtureNew(t)
	e, _, _ := sourceUnitCommitted(t, f)
	old := *e.candidate.Receipt
	original, _ := json.Marshal(f.server.forest.Children["account-root"].Children["data-root"].Children["record-a"].Metadata)
	reopened := stagedTestServer(t, f.server.config.Process.DatabasePath)
	if err := reopened.loadFromFile(f.server.statePath()); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ConfigurePersonalSource(f.config); err != nil {
		t.Fatal(err)
	}
	p := reopened.personalSource.Load()
	input := e.prepared
	got, err := p.preparePersonal(sourceUnitRequest(&sourceUnitFixture{p: p, config: f.config, actor: f.actor}, "provision.resolve", input))
	if err != nil {
		t.Fatal(err)
	}
	c := got.(SourceProspectiveCandidate)
	if c.RootID != old.OwnerRef.RootID || c.OwnerID != old.OwnerRef.OwnerID || c.Receipt == nil {
		t.Fatal("restart reallocated")
	}
	current, _ := json.Marshal(reopened.forest.Children["account-root"].Children["data-root"].Children["record-a"].Metadata)
	if string(original) != string(current) {
		t.Fatal("unknown/source bag changed")
	}
}
