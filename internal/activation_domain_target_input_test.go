// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"errors"
	"testing"
)

type targetInputTestProduct struct {
	*evaluationTestProduct
	t                      *testing.T
	binds, creates, fields int
	err                    error
}

type targetInputTestProjection struct{ product *targetInputTestProduct }

func (p *targetInputTestProduct) BindTargetInput(DomainInput) (DomainTargetInput, error) {
	p.binds++
	return targetInputTestProjection{p}, p.err
}

func (p targetInputTestProjection) NativeCreates(DomainOwnedScope, string) bool {
	p.product.creates++
	return false
}

func (p targetInputTestProjection) TargetFields(_ DomainOwnedScope, record DomainRecord) []string {
	p.product.fields++
	if err := evaluationCheckThenMutate(record); err != nil {
		p.product.t.Fatal("parsed target callback metadata not isolated", err)
	}
	return nil
}

func TestDomainTargetInputBindsOncePerLockWithoutCachingPolicyOrRecords(t *testing.T) {
	x := evaluationFixture(t, "command")
	product := &targetInputTestProduct{evaluationTestProduct: x.product, t: t}
	x.d.products["manifest"], x.entry.product = product, product
	for pass := 1; pass <= 2; pass++ {
		x.f.server.forestMutex.Lock()
		authorize := x.f.server.domainAuthorizer(x.d, x.entry)
		evaluationAuthorizeMany(t, authorize, evaluationAccess(x.entry), 20)
		x.f.server.forestMutex.Unlock()
		if product.binds != pass || product.creates != pass*20 || product.fields != pass*20 || x.policy.calls != pass*80 {
			t.Fatal("parsed input changed per-target current authorization or escaped its lock lifetime")
		}
	}
	if err := evaluationCheckThenMutate(stagedTestDomainRecord(t, x)); err != nil {
		t.Fatal("parsed target callback poisoned actual native metadata", err)
	}
}

func TestDomainTargetInputBinderFailureDeniesBeforePolicy(t *testing.T) {
	x := evaluationFixture(t, "command")
	want := errors.New("invalid parsed input")
	product := &targetInputTestProduct{evaluationTestProduct: x.product, t: t, err: want}
	x.d.products["manifest"], x.entry.product = product, product
	x.f.server.forestMutex.Lock()
	defer x.f.server.forestMutex.Unlock()
	err := x.f.server.domainAuthorizer(x.d, x.entry)(evaluationAccess(x.entry))
	if !errors.Is(err, want) || product.binds != 1 || x.policy.calls != 0 || product.fields != 0 {
		t.Fatal("failed parsed input was admitted")
	}
}

func TestDomainTargetInputFreshCurrentPolicyDenialStillStopsNextTarget(t *testing.T) {
	x := evaluationFixture(t, "command")
	product := &targetInputTestProduct{evaluationTestProduct: x.product, t: t}
	x.d.products["manifest"], x.entry.product = product, product
	x.f.server.forestMutex.Lock()
	defer x.f.server.forestMutex.Unlock()
	authorize := x.f.server.domainAuthorizer(x.d, x.entry)
	evaluationAuthorizeMany(t, authorize, evaluationAccess(x.entry), 1)
	x.policy.denyAt = x.policy.calls + 1
	if err := authorize(evaluationAccess(x.entry)); err == nil || product.binds != 1 || product.fields != 1 {
		t.Fatal("prepared request bypassed a newly denying current policy")
	}
}
