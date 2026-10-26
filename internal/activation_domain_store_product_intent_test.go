// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"strings"
	"testing"
)

func TestNativeProductResultClosedPairedGrammar(t *testing.T) {
	binding := stagedBinding{ProductID: "manifest", ScopeID: "scope", AccountID: "account", RootID: "root", BindingRevision: "owner-profile"}
	payload := nativeStoreProductResult{Records: []nativeStoreReceiptRecord{{Family: "business:job", Key: "canonical", NativeID: "native", Version: strings.Repeat("a", 64), Data: map[string]interface{}{"id": "canonical", "account_id": "account", "name": "public"}}}, Result: []byte("null")}
	raw, _ := CanonicalDomainJSON(payload)
	receipt := stagedReceipt{Command: stagedCommand{AccountID: "account", ScopeID: "scope", Action: nativeStoreCommand}, Targets: []stagedTarget{{NodeID: "native"}}, ProductIntent: raw}
	if err := validateProductReceiptIntent(binding, receipt, 10000); err != nil {
		t.Fatal(err)
	}
	receipt.Targets = nil
	if validateProductReceiptIntent(binding, receipt, 10000) == nil {
		t.Fatal("result invented unpaired native alias")
	}
	if _, err := decodeProductIntent([]byte(`{"records":[],"result":null,"grant":"owner"}`), 10000); err == nil {
		t.Fatal("undeclared authority field accepted")
	}
	if _, err := decodeProductIntent([]byte(`{"records":[{"family":"job","key":"id","native_id":"native","version":"v","data":{}}],"result":{"token":"secret"}}`), 10000); err == nil {
		t.Fatal("unclosed retained result bag accepted")
	}
}
func TestProductV2ExplicitIntentBindsNativeReceiptAndCanonicalFields(t *testing.T) {
	binding := stagedBinding{ProductID: "manifest", ScopeID: "scope", AccountID: "account", RootID: "root", BindingRevision: "owner-profile"}
	scope := DomainScope{AccountID: "account", Product: "manifest"}
	action := "role.define"
	resource := DomainResource{AccountID: "account", Kind: "root", ResourceID: "root"}
	intent := DomainIntent{ContractRevision: nativeProductV2, Scope: scope, Binding: DomainBinding{Scope: scope, RootID: "root", BindingRevision: "owner-profile"}, Mode: "command", Operation: &action, Method: "POST", Target: "/fixture/role.define", RequestFingerprint: strings.Repeat("b", 64), Resources: []DomainResource{resource}, Fields: []DomainFieldSet{{Resource: resource, Fields: []string{"children", "id"}}}}
	raw, _ := CanonicalDomainJSON(intent)
	receipt := stagedReceipt{Command: stagedCommand{AccountID: "account", ScopeID: "scope", Action: action, BodySHA256: intent.RequestFingerprint}, ProductIntent: raw}
	if err := validateProductReceiptIntent(binding, receipt, 10000); err != nil {
		t.Fatal(err)
	}
	receipt.Command.BodySHA256 = strings.Repeat("c", 64)
	if validateProductReceiptIntent(binding, receipt, 10000) == nil {
		t.Fatal("historical product intent fingerprint was rebound")
	}
	receipt.ProductIntent = nil
	if err := validateProductReceiptIntent(binding, receipt, 10000); err != nil {
		t.Fatal("legacy command was silently reclassified /.2", err)
	}
	receipt.Command.Action = nativeStoreCommand
	if validateProductReceiptIntent(binding, receipt, 10000) == nil {
		t.Fatal("native command missing explicit retained result accepted")
	}
}
func TestOwnerPolicyRequiresCurrentPinnedBaseRevisionAndSession(t *testing.T) {
	policy := &domainOwnerPolicy{key: "acl"}
	actor := DomainVerified{Kind: "human", PrincipalID: "member", GrantRevision: "current", ExpiresAt: domainNow() + 30}
	record := DomainRecord{Metadata: map[string]interface{}{"acl": map[string]interface{}{"contractRevision": "lj.domain.acl/1", "principals": map[string]interface{}{"member": map[string]interface{}{"read": map[string]interface{}{"fields": []string{"id"}, "targetGrantRevision": "current"}}}}}}
	access := DomainAccess{Operation: "read", Fields: []string{"id"}}
	if err := policy.AuthorizeLocked(actor, access, record); err != nil {
		t.Fatal(err)
	}
	actor.GrantRevision = "revoked"
	if policy.AuthorizeLocked(actor, access, record) == nil {
		t.Fatal("static pinned native ACL bypassed current BASE rights")
	}
	actor.GrantRevision = "current"
	policy.sessionFenced = func(DomainVerified) bool { return true }
	if policy.AuthorizeLocked(actor, access, record) == nil {
		t.Fatal("fenced actor session admitted")
	}
}
