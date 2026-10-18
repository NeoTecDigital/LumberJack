// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "testing"

type privateViewTestProduct struct {
	*evaluationTestProduct
	t *testing.T
}

func (p privateViewTestProduct) Project(id string, intent DomainIntent, owned DomainOwnedScope, view DomainView) ([]byte, error) {
	if err := evaluationCheckThenMutate(view.Records["record-a"]); err != nil {
		p.t.Fatal("Project received another callback's metadata mutation", err)
	}
	delete(view.Records, "role-a")
	return p.domainTestProduct.Project(id, intent, owned, view)
}

func TestDomainPrivateViewResolveAndProjectCannotMutateActualForest(t *testing.T) {
	x := evaluationFixture(t, "read")
	x.product.mutate = true
	x.d.products["manifest"] = privateViewTestProduct{x.product, t}
	begin := domainTestBegin(t, x.f, domainTestInput(t, x.f, "read", "private-view"))
	domainTestReceive(t, x.f, begin)
	if err := evaluationCheckThenMutate(stagedTestDomainRecord(t, x)); err != nil {
		t.Fatal("Resolve/Project modified live forest metadata", err)
	}
	if x.policy.calls == 0 || x.product.resolves == 0 {
		t.Fatal("private view skipped fresh native Resolve/policy evaluation")
	}
}

func TestDomainPrivateViewDefaultSnapshotStillReturnsIndependentCopies(t *testing.T) {
	x := evaluationFixture(t, "read")
	x.f.server.forestMutex.RLock()
	defer x.f.server.forestMutex.RUnlock()
	view, err := x.f.server.domainViewLocked(x.entry.owned)
	if err != nil {
		t.Fatal(err)
	}
	evaluationMutateRecord(view.Records["record-a"])
	if err := evaluationCheckThenMutate(stagedTestDomainRecord(t, x)); err != nil {
		t.Fatal("default view API exposed private forest references", err)
	}
}
