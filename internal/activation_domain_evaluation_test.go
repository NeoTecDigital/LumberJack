// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"fmt"
	"testing"
)

func TestDomainEvaluationResolvesOneCurrentViewFor20And60Targets(t *testing.T) {
	for _, count := range []int{20, 60} {
		t.Run(fmt.Sprint(count), func(t *testing.T) { evaluationCountTargets(t, count) })
	}
}

func TestDomainEvaluationActualHandoffSeedsItsAlreadyResolvedCurrentView(t *testing.T) {
	x := evaluationFixture(t, "command")
	request := domainTestInput(t, x.f, "command", "evaluation-gate")
	begin := domainTestBegin(t, x.f, request)
	domainTestReceive(t, x.f, begin)
	x.product.resolves, x.policy.calls = 0, 0
	handoff := domainTestControl(x.f, begin, "handoff")
	handoff.Proof = "handoff-evaluation-gate"
	if _, err := x.f.server.DomainControl(context.Background(), handoff); err != nil {
		t.Fatal(err)
	}
	if x.product.resolves != 1 || x.policy.calls != 7 {
		t.Fatalf("handoff rebuilt a resolved view or skipped authorization: Resolve=%d policy=%d", x.product.resolves, x.policy.calls)
	}
}

func evaluationCountTargets(t *testing.T, count int) {
	t.Helper()
	x := evaluationFixture(t, "command")
	x.f.server.forestMutex.Lock()
	defer x.f.server.forestMutex.Unlock()
	authorize := x.f.server.domainAuthorizer(x.d, x.entry)
	evaluationAuthorizeMany(t, authorize, evaluationAccess(x.entry), count)
	if x.product.resolves != 1 || x.policy.calls != count*4 {
		t.Fatalf("Resolve/view builds=%d, fresh policy calls=%d, targets=%d", x.product.resolves, x.policy.calls, count)
	}
}

func TestDomainEvaluationReplayStillAuthorizesEveryTargetFromOneSeededView(t *testing.T) {
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
	for _, count := range []int{20, 60} {
		authorize := x.f.server.domainEvaluationAuthorizer(x.d, x.entry, evaluation)
		if err = authorizeStagedReplay(authorize, x.entry.owned.Binding, evaluationTargets(x.entry, count)); err != nil {
			t.Fatal(err)
		}
	}
	if x.product.resolves != 1 || x.policy.calls != 80*4 {
		t.Fatalf("seeded Resolve/view builds=%d, fresh replay policy calls=%d", x.product.resolves, x.policy.calls)
	}
}

func TestDomainEvaluationResolveAndPolicyMutationCannotPoisonPrivateRecords(t *testing.T) {
	x := evaluationFixture(t, "command")
	x.product.mutate, x.policy.mutate = true, true
	x.f.server.forestMutex.Lock()
	defer x.f.server.forestMutex.Unlock()
	authorize := x.f.server.domainAuthorizer(x.d, x.entry)
	evaluationAuthorizeMany(t, authorize, evaluationAccess(x.entry), 60)
	if x.product.resolves != 1 || x.policy.calls != 60*4 {
		t.Fatal("callback mutation skipped subsequent current authorization")
	}
	if err := evaluationCheckThenMutate(stagedTestDomainRecord(t, x)); err != nil {
		t.Fatal("callbacks mutated the actual forest", err)
	}
}

func stagedTestDomainRecord(t *testing.T, x evaluationTestFixture) DomainRecord {
	t.Helper()
	native := stagedTestRecord(t, x.f.server.forest)
	copy, err := cloneStagedMetadata(native.Metadata, x.entry.owned.Bounds)
	if err != nil {
		t.Fatal(err)
	}
	return DomainRecord{ID: native.ID, Kind: native.Kind, Metadata: copy}
}

func TestDomainEvaluationNewLockAndNewAuthorizerRebuildAndSeeRevocation(t *testing.T) {
	x := evaluationFixture(t, "command")
	x.f.server.forestMutex.Lock()
	evaluationAuthorizeMany(t, x.f.server.domainAuthorizer(x.d, x.entry), evaluationAccess(x.entry), 20)
	x.f.server.forestMutex.Unlock()
	x.f.server.forestMutex.Lock()
	defer x.f.server.forestMutex.Unlock()
	native := stagedTestRecord(t, x.f.server.forest)
	native.Metadata["ownerAcl"] = map[string]interface{}{"contractRevision": "lj.domain.acl/1", "principals": map[string]interface{}{}}
	err := x.f.server.domainAuthorizer(x.d, x.entry)(evaluationAccess(x.entry))
	if err == nil || x.product.resolves != 2 {
		t.Fatalf("new lock reused old authority or view: Resolve=%d, err=%v", x.product.resolves, err)
	}
}

func TestDomainEvaluationChangedCurrentPolicyIsNotMemoized(t *testing.T) {
	x := evaluationFixture(t, "command")
	x.f.server.forestMutex.Lock()
	defer x.f.server.forestMutex.Unlock()
	authorize := x.f.server.domainAuthorizer(x.d, x.entry)
	evaluationAuthorizeMany(t, authorize, evaluationAccess(x.entry), 20)
	x.policy.denyAt = x.policy.calls + 1
	if err := authorize(evaluationAccess(x.entry)); err == nil || x.product.resolves != 1 {
		t.Fatal("cached view bypassed fresh policy denial", err)
	}
}
