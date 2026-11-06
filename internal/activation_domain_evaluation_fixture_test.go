// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"testing"
)

type evaluationTestProduct struct {
	domainTestProduct
	resolves int
	mutate   bool
}

func (p *evaluationTestProduct) Resolve(input DomainInput, owned DomainOwnedScope, view DomainView) (DomainIntent, error) {
	p.resolves++
	if p.mutate {
		evaluationMutateRecord(view.Records["record-a"])
		delete(view.Records, "role-a")
	}
	return p.domainTestProduct.Resolve(input, owned, view)
}

type evaluationTestPolicy struct {
	delegate DomainPolicy
	calls    int
	creates  int
	denyAt   int
	mutate   bool
}

func (p *evaluationTestPolicy) AuthorizeLocked(actor DomainVerified, access DomainAccess, record DomainRecord) error {
	p.calls++
	if p.calls == p.denyAt {
		return fmt.Errorf("test current policy revoked")
	}
	if err := p.delegate.AuthorizeLocked(actor, access, record); err != nil {
		return err
	}
	if p.mutate && record.ID == "record-a" {
		return evaluationCheckThenMutate(record)
	}
	return nil
}

func (p *evaluationTestPolicy) CreateACLLocked(actor DomainVerified, operation, kind string, root DomainRecord) (interface{}, error) {
	p.creates++
	return p.delegate.CreateACLLocked(actor, operation, kind, root)
}

type evaluationTestFixture struct {
	f       *domainTestFixture
	d       *domainEngine
	entry   *domainEntry
	product *evaluationTestProduct
	policy  *evaluationTestPolicy
}

func evaluationFixture(t *testing.T, mode string) evaluationTestFixture {
	t.Helper()
	f := domainTestConfigured(t)
	d := f.server.domain
	product := &evaluationTestProduct{}
	d.products["manifest"] = product
	request := domainTestInput(t, f, mode, "evaluation")
	f.server.forestMutex.RLock()
	intent, owned, _, err := f.server.resolveDomainLocked(d, request.DomainInput)
	f.server.forestMutex.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	actor := DomainVerified{PrincipalID: "external-human", SessionID: "session-a", Kind: "human", Scope: intent.Scope, Intent: intent, ExpiresAt: domainNow() + 30}
	entry := &domainEntry{actor: actor, intent: intent, input: request.DomainInput, owned: owned, product: product}
	policy := &evaluationTestPolicy{delegate: d.policy}
	d.policy = policy
	product.resolves = 0
	return evaluationTestFixture{f, d, entry, product, policy}
}

func evaluationAccess(entry *domainEntry) stagedAccess {
	return stagedAccess{Binding: entry.owned.Binding, PrincipalID: entry.actor.PrincipalID,
		Action: "associate.role.attach", NodeID: "record-a", Kind: "synthetic-record", Fields: []string{"roleIds"}}
}

func evaluationTargets(entry *domainEntry, count int) stagedReceipt {
	access := evaluationAccess(entry)
	receipt := stagedReceipt{Command: stagedCommand{PrincipalID: access.PrincipalID, Action: access.Action}}
	for i := 0; i < count; i++ {
		receipt.Targets = append(receipt.Targets, stagedTarget{NodeID: access.NodeID, Kind: access.Kind, Fields: append([]string(nil), access.Fields...)})
	}
	return receipt
}

func evaluationAuthorizeMany(t *testing.T, authorize stagedAuthorizer, access stagedAccess, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		if err := authorize(access); err != nil {
			t.Fatal(err)
		}
	}
}

func evaluationMutateRecord(record DomainRecord) {
	record.Metadata["label"] = "callback-poison"
	unknown := record.Metadata["unknown"].(map[string]interface{})
	unknown["array"].([]interface{})[0] = "callback-poison"
	unknown["object"].(map[string]interface{})["unknown-key"] = "callback-poison"
	delete(record.Metadata, "ownerAcl")
}

func evaluationCheckThenMutate(record DomainRecord) error {
	unknown := record.Metadata["unknown"].(map[string]interface{})
	if record.Metadata["label"] != "original" || unknown["array"].([]interface{})[0] != " exact " || unknown["object"].(map[string]interface{})["unknown-key"] != "unmodified" {
		return fmt.Errorf("callback received previously mutated private metadata")
	}
	evaluationMutateRecord(record)
	return nil
}
