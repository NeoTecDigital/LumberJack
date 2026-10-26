// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "testing"

func TestDomainSnapshotCacheFreshViewsCannotMutateCachedNodesOrOtherViews(t *testing.T) {
	x := evaluationFixture(t, "command")
	x.f.server.forestMutex.RLock()
	defer x.f.server.forestMutex.RUnlock()
	first, err := x.f.server.domainViewLocked(x.entry.owned)
	if err != nil {
		t.Fatal(err)
	}
	evaluationMutateRecord(first.Records["record-a"])
	delete(first.Records, "role-a")
	second, err := x.f.server.domainViewLocked(x.entry.owned)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := second.Records["role-a"]; !present {
		t.Fatal("a callback deleted a cached native record")
	}
	if err = evaluationCheckThenMutate(second.Records["record-a"]); err != nil {
		t.Fatal("a callback poisoned another freshly cloned view", err)
	}
	if err = evaluationCheckThenMutate(stagedTestDomainRecord(t, x)); err != nil {
		t.Fatal("a callback poisoned the actual forest", err)
	}
}

func TestDomainSnapshotCacheWriterBypassesBetweenTwoMutationsInSameLockHold(t *testing.T) {
	x := evaluationFixture(t, "command")
	snapshotWarmView(t, x)
	x.f.server.forestMutex.Lock()
	defer x.f.server.forestMutex.Unlock()
	before, err := x.f.server.domainViewLocked(x.entry.owned)
	if err != nil {
		t.Fatal(err)
	}
	record := stagedTestRecord(t, x.f.server.forest)
	record.Metadata["label"] = "first-write"
	first, err := x.f.server.domainViewLocked(x.entry.owned)
	if err != nil {
		t.Fatal(err)
	}
	record.Metadata["label"] = "second-write"
	second, err := x.f.server.domainViewLocked(x.entry.owned)
	if err != nil {
		t.Fatal(err)
	}
	if first.Records[record.ID].Metadata["label"] != "first-write" || second.Records[record.ID].Metadata["label"] != "second-write" || before.Revision == first.Revision || first.Revision == second.Revision {
		t.Fatal("active writer reused an earlier structural/content snapshot")
	}
	if len(x.f.server.domainSnapshots.entries) != 0 {
		t.Fatal("an active writer retained a structural snapshot")
	}
}

func snapshotWarmView(t *testing.T, x evaluationTestFixture) {
	t.Helper()
	x.f.server.forestMutex.RLock()
	defer x.f.server.forestMutex.RUnlock()
	if _, err := x.f.server.domainViewLocked(x.entry.owned); err != nil {
		t.Fatal(err)
	}
}

func TestDomainSnapshotCacheRechecksCurrentScopeAndNarrowerBoundsOnEveryCall(t *testing.T) {
	x := evaluationFixture(t, "command")
	x.f.server.forestMutex.RLock()
	defer x.f.server.forestMutex.RUnlock()
	if _, err := x.f.server.domainViewLocked(x.entry.owned); err != nil {
		t.Fatal(err)
	}
	narrow := x.entry.owned
	narrow.Bounds.MaxNodes = 1
	if _, err := x.f.server.domainViewLocked(narrow); err == nil {
		t.Fatal("cached closure bypassed a different exact bound")
	}
	scope := x.f.server.stagedScopes[x.entry.owned.Binding.ScopeID]
	scope.configured = false
	if _, err := x.f.server.domainViewLocked(x.entry.owned); err != errStagedUnconfigured {
		t.Fatal("cached nodes bypassed current configured state", err)
	}
	scope.configured, scope.reconciled = true, false
	if _, err := x.f.server.domainViewLocked(x.entry.owned); err != errStagedUnconfigured {
		t.Fatal("cached nodes bypassed current reconciled state", err)
	}
	scope.reconciled = true
	scope.descriptor.Binding.BindingRevision = "changed"
	if _, err := x.f.server.domainViewLocked(x.entry.owned); err != errStagedUnconfigured {
		t.Fatal("cached nodes bypassed current owner binding", err)
	}
}

func TestDomainSnapshotCacheKeepsReadPendingAndCurrentPolicyRevocationChecks(t *testing.T) {
	x := evaluationFixture(t, "read")
	x.f.server.forestMutex.RLock()
	defer x.f.server.forestMutex.RUnlock()
	if _, _, _, err := x.f.server.resolveDomainLocked(x.d, x.entry.input); err != nil {
		t.Fatal(err)
	}
	authorize := x.f.server.domainAuthorizer(x.d, x.entry)
	evaluationAuthorizeMany(t, authorize, evaluationAccess(x.entry), 1)
	x.policy.denyAt = x.policy.calls + 1
	if err := x.f.server.domainAuthorizer(x.d, x.entry)(evaluationAccess(x.entry)); err == nil {
		t.Fatal("cached structural snapshot bypassed current policy revocation")
	}
	scope := x.f.server.stagedScopes[x.entry.owned.Binding.ScopeID]
	scope.pending = &stagedPending{key: "pending-after-snapshot"}
	if _, _, _, err := x.f.server.resolveDomainLocked(x.d, x.entry.input); err != errStagedPending {
		t.Fatal("cached structural snapshot bypassed pending read guard", err)
	}
}
