// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import "testing"

// The private application adapter has one extra callback absent from the
// upstream checkpoint. It must not receive retained evaluation metadata either.
type evaluationFieldsProduct struct {
	*evaluationTestProduct
	t     *testing.T
	calls int
}

func (p *evaluationFieldsProduct) TargetFields(input DomainInput, owned DomainOwnedScope, record DomainRecord) []string {
	p.calls++
	if err := evaluationCheckThenMutate(record); err != nil {
		p.t.Fatal("TargetFields received another callback's mutation", err)
	}
	return nil
}

func TestDomainEvaluationTargetFieldsCannotPoisonPrivateRecords(t *testing.T) {
	x := evaluationFixture(t, "command")
	product := &evaluationFieldsProduct{evaluationTestProduct: x.product, t: t}
	x.f.server.forestMutex.Lock()
	defer x.f.server.forestMutex.Unlock()
	x.d.products["manifest"], x.entry.product = product, product
	authorize := x.f.server.domainAuthorizer(x.d, x.entry)
	evaluationAuthorizeMany(t, authorize, evaluationAccess(x.entry), 60)
	if product.calls != 60 || x.product.resolves != 1 || x.policy.calls != 60*4 {
		t.Fatal("TargetFields isolation skipped native per-target authorization")
	}
	if err := evaluationCheckThenMutate(stagedTestDomainRecord(t, x)); err != nil {
		t.Fatal("TargetFields mutated the native forest", err)
	}
}
