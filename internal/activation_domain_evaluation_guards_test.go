// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "testing"

func TestDomainEvaluationChecksExpiryBindingIntentAndStagedStateForEveryTarget(t *testing.T) {
	for _, change := range []string{"expiry", "access-binding", "scope-binding", "configured", "reconciled", "intent"} {
		t.Run(change, func(t *testing.T) { evaluationChangedGuard(t, change) })
	}
}

func evaluationChangedGuard(t *testing.T, change string) {
	t.Helper()
	x := evaluationFixture(t, "command")
	x.f.server.forestMutex.Lock()
	defer x.f.server.forestMutex.Unlock()
	authorize := x.f.server.domainAuthorizer(x.d, x.entry)
	access := evaluationAccess(x.entry)
	evaluationAuthorizeMany(t, authorize, access, 20)
	scope := x.f.server.stagedScopes[x.entry.owned.Binding.ScopeID]
	switch change {
	case "expiry":
		x.entry.actor.ExpiresAt = domainNow() - 1
	case "access-binding":
		access.Binding.BindingRevision = "changed"
	case "scope-binding":
		scope.descriptor.Binding.BindingRevision = "changed"
	case "configured":
		scope.configured = false
	case "reconciled":
		scope.reconciled = false
	case "intent":
		x.entry.intent.RequestFingerprint = stagedHash([]byte("changed"))
	}
	if err := authorize(access); err == nil {
		t.Fatal("cached evaluation bypassed current guard", change)
	}
	if x.product.resolves != 1 {
		t.Fatal("guard reloaded the whole view instead of checking current state")
	}
}

func TestDomainEvaluationReadPendingStateIsRecheckedPerTarget(t *testing.T) {
	x := evaluationFixture(t, "read")
	x.f.server.forestMutex.Lock()
	defer x.f.server.forestMutex.Unlock()
	authorize := x.f.server.domainAuthorizer(x.d, x.entry)
	access := evaluationAccess(x.entry)
	evaluationAuthorizeMany(t, authorize, access, 20)
	scope := x.f.server.stagedScopes[x.entry.owned.Binding.ScopeID]
	scope.pending = &stagedPending{key: "new-pending"}
	if err := authorize(access); err != errStagedPending {
		t.Fatal("pending scope was hidden by cached view", err)
	}
}

func TestDomainEvaluationPerTargetPolicyRevocationRemainsCurrent(t *testing.T) {
	x := evaluationFixture(t, "command")
	x.f.server.forestMutex.Lock()
	defer x.f.server.forestMutex.Unlock()
	authorize := x.f.server.domainAuthorizer(x.d, x.entry)
	evaluationAuthorizeMany(t, authorize, evaluationAccess(x.entry), 20)
	if x.policy.calls != 20*4 {
		t.Fatal("current policy was not checked for every target authorization", x.policy.calls)
	}
	x.policy.denyAt = x.policy.calls + 1
	if err := authorize(evaluationAccess(x.entry)); err == nil || x.policy.calls != 20*4+1 {
		t.Fatal("cached resolution bypassed new current policy revocation", err)
	}
	if x.product.resolves != 1 {
		t.Fatal("policy recheck rebuilt the full view")
	}
}

func TestDomainEvaluationSeededReplayCannotReuseExpiredOrReboundAuthority(t *testing.T) {
	x := evaluationFixture(t, "command")
	x.f.server.forestMutex.RLock()
	defer x.f.server.forestMutex.RUnlock()
	current, _, view, err := x.f.server.resolveDomainLocked(x.d, x.entry.input)
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := newDomainEvaluation(current, view)
	if err != nil {
		t.Fatal(err)
	}
	x.entry.actor.ExpiresAt = domainNow() - 1
	err = authorizeStagedReplay(x.f.server.domainEvaluationAuthorizer(x.d, x.entry, evaluation), x.entry.owned.Binding, evaluationTargets(x.entry, 60))
	if err == nil || x.policy.calls != 0 {
		t.Fatal("seeded replay bypassed expired authority", err)
	}
}
