// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"testing"
)

func TestPersonalSourceCurrentOwnedContextNoLegacyProfileOrProjectGuess(t *testing.T) {
	f := sourceUnitFixtureNew(t)
	e, _, _ := sourceUnitCommitted(t, f)
	r := e.candidate.Receipt
	intent := PersonalSourceIntent{ContractRevision: "activation-personal-handoff/0.1", Scope: f.grant.Scope, OwnerRef: r.OwnerRef, BindingRevision: r.BindingRevision, Action: "workspace.read", Method: "GET", Target: "/workspace", BodySHA256: stagedHash(nil), Resources: []SourceResourceRef{}, Fields: []SourceFieldSet{}}
	original := sourceResolvedRequestBinding{"GET", "/workspace", stagedHash(nil)}
	intent.RequestSHA256 = sourceCommandKey(original)
	got, err := f.p.bindingOpen(sourceUnitRequest(f, "binding.open", sourceBindingOpen{f.actor, f.grant, intent}))
	if err != nil {
		t.Fatal(err)
	}
	binding := got.(sourceBindingResult)
	request := sourceContextRequest{binding.Binding.BindingRevision, sourceOriginalRequest{"GET", "/workspace", []byte{}}, binding.LeaseRef}
	resolved, err := f.p.resolveContext(sourceUnitRequest(f, "context.resolve", request))
	if err != nil {
		t.Fatalf("context failure %#v", err)
	}
	contexts := resolved.(sourceResolvedRequest).Contexts
	if len(contexts) != 1 || contexts[0].NodeID != r.OwnerRef.RootID || contexts[0].WorkspaceID != nil {
		t.Fatal("scope/Project guessed")
	}
	request.Request.Target = "/query"
	if _, err = f.p.resolveContext(sourceUnitRequest(f, "context.resolve", request)); err == nil {
		t.Fatal("unimplemented family claimed supported")
	}
	f.server.forest.Children[r.OwnerRef.RootID].CreatedBy = "unit-wrong-owner"
	if _, err = f.p.bindingRecheck(sourceUnitRequest(f, "binding.recheck", sourceBindingRecheck{binding.LeaseRef, f.actor, f.grant, intent})); err == nil {
		t.Fatal("current native ownership ignored")
	}
}
