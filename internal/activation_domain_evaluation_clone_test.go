// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "testing"

func TestDomainEvaluationResolveCopyPreservesOtherViewFieldsAndIsolatesNestedMetadata(t *testing.T) {
	view := DomainView{Binding: stagedTestBinding(), Revision: "test-revision",
		ACLMetadataKey: "ownerAcl", AllocateID: func() (string, error) { return "test-id", nil },
		CreateACL: func(string) (interface{}, error) { return "test-acl", nil },
		Records: map[string]DomainRecord{"r": {ID: "r", Metadata: map[string]interface{}{
			"typed": []string{"original"}, "map": map[string]string{"key": "original"}, "nested": []interface{}{map[string]interface{}{"key": "original"}}}}}}
	copy, err := cloneDomainResolveView(view, stagedTestBounds())
	if err != nil {
		t.Fatal(err)
	}
	copy.Records["r"].Metadata["typed"].([]string)[0] = "changed"
	copy.Records["r"].Metadata["map"].(map[string]string)["key"] = "changed"
	copy.Records["r"].Metadata["nested"].([]interface{})[0].(map[string]interface{})["key"] = "changed"
	delete(copy.Records, "r")
	metadata := view.Records["r"].Metadata
	if metadata["typed"].([]string)[0] != "original" || metadata["map"].(map[string]string)["key"] != "original" || metadata["nested"].([]interface{})[0].(map[string]interface{})["key"] != "original" {
		t.Fatal("callback view retained private nested aliases")
	}
	id, idErr := copy.AllocateID()
	acl, aclErr := copy.CreateACL("associate")
	if copy.Binding != view.Binding || copy.Revision != view.Revision || copy.ACLMetadataKey != "ownerAcl" || id != "test-id" || acl != "test-acl" || idErr != nil || aclErr != nil {
		t.Fatal("record isolation dropped unrelated normal DomainView fields")
	}
}

type evaluationCreatePolicy struct{ rootChecks, creates, recordChecks int }

func (p *evaluationCreatePolicy) AuthorizeLocked(actor DomainVerified, access DomainAccess, record DomainRecord) error {
	if record.ID == "data-root" {
		p.rootChecks++
		if record.Metadata["label"] != "original-root" {
			return errStagedUnconfigured
		}
		record.Metadata["label"] = "policy-poison"
		return nil
	}
	p.recordChecks++
	record.Metadata["ownerAcl"].(map[string]interface{})["value"] = "policy-poison"
	return nil
}

func (p *evaluationCreatePolicy) CreateACLLocked(actor DomainVerified, operation, kind string, root DomainRecord) (interface{}, error) {
	p.creates++
	if root.Metadata["label"] != "original-root" {
		return nil, errStagedUnconfigured
	}
	root.Metadata["label"] = "create-poison"
	return map[string]interface{}{"value": "original-acl"}, nil
}

func TestDomainEvaluationDefinitionPoliciesGetFreshRootAndRecordPerCallback(t *testing.T) {
	x := evaluationFixture(t, "command")
	policy := &evaluationCreatePolicy{}
	x.d.policy = policy
	operation := "associate.create.define"
	x.entry.intent.Operation = &operation
	root := DomainRecord{ID: "data-root", Kind: "test-root", Metadata: map[string]interface{}{"label": "original-root"}}
	view := DomainView{Records: map[string]DomainRecord{root.ID: root}}
	access := stagedAccess{NodeID: "new-associate", Kind: "synthetic-record", Action: operation}
	for i := 0; i < 20; i++ {
		if err := x.d.authorizeDefinitionTarget(x.entry, view, access, []string{"label"}); err != nil {
			t.Fatal("definition callback poisoned later private authorization", err)
		}
	}
	if policy.rootChecks != 20 || policy.creates != 20 || policy.recordChecks != 20 || root.Metadata["label"] != "original-root" {
		t.Fatal("definition callbacks were cached or shared private metadata")
	}
}
