// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"testing"
)

func TestPNGActualReadGrantFutureNodesRevokeAndRestart(t *testing.T) {
	if *pngProfileArtifact == "" {
		t.Skip("explicit protected profile required")
	}
	config := pngProtectedConfig(t, *pngProfileArtifact)
	scope := engine.DomainScope{AccountID: "actual-template-organization", Product: "manifest"}
	input := engine.EnrollmentInput{ContractRevision: engine.EnrollmentProofRevision, RequestID: "template-provision", Proof: "template_provision", Request: engine.EnrollmentRequest{ContractRevision: engine.EnrollmentRevision, Scope: scope, CommandID: "template-provision", ExpectedRevision: "absent", Operation: engine.EnrollmentProvision, ProfileRef: config.ProvisioningProfile.ProfileRef}}
	authority := pngEnrolledVerifier(t, &config, input)
	directory := t.TempDir()
	handle := openPNGFixture(t, directory, config)
	_ = pngActualEnrollment(t, handle, config, input, authority)
	pngTemplateAccessChange(t, handle, config, authority, scope, engine.EnrollmentReadGrant)
	pngTemplateCreate(t, handle, config, authority, scope, "after-grant")
	pngTemplateRead(t, handle, config, authority.domain, scope, "after-grant")
	closePNGFixture(t, handle)
	handle = openPNGFixture(t, directory, config)
	pngTemplateCreate(t, handle, config, authority, scope, "after-restart")
	pngTemplateRead(t, handle, config, authority.domain, scope, "after-restart")
	pngTemplateAccessChange(t, handle, config, authority, scope, engine.EnrollmentReadRevoke)
	pngTemplateCreate(t, handle, config, authority, scope, "after-revoke")
	pngTemplateDeny(t, handle, authority.domain, scope, "after-grant")
	pngTemplateDeny(t, handle, authority.domain, scope, "after-revoke")
	closePNGFixture(t, handle)
	handle = openPNGFixture(t, directory, config)
	pngTemplateDeny(t, handle, authority.domain, scope, "after-restart")
	pngTemplateDeny(t, handle, authority.domain, scope, "after-revoke")
	closePNGFixture(t, handle)
}
func pngTemplateAccessChange(t *testing.T, handle *Handle, config DomainConfig, authority *pngEnrolledAuthority, scope engine.DomainScope, operation string) {
	graph := pngActualGraphRead(t, handle, config, authority.domain, scope)
	target := "fixture-member"
	input := engine.EnrollmentInput{ContractRevision: engine.EnrollmentProofRevision, RequestID: operation, Proof: "template_" + domainFixtureSHA(operation), Request: engine.EnrollmentRequest{ContractRevision: engine.EnrollmentRevision, Scope: scope, CommandID: operation, ExpectedRevision: graph["revision"].(string), Operation: operation, TargetPrincipalID: &target, ProfileRef: config.ProvisioningProfile.ProfileRef}}
	authority.domain.mu.Lock()
	authority.input, authority.lease = input, nil
	authority.domain.mu.Unlock()
	_ = pngActualEnrollment(t, handle, config, input, authority)
}
func pngTemplateCreate(t *testing.T, handle *Handle, config DomainConfig, authority *pngEnrolledAuthority, scope engine.DomainScope, key string) {
	graph := pngActualGraphRead(t, handle, config, authority.domain, scope)
	request := pngstore.Request{ContractRevision: pngstore.Revision, Scope: scope, Action: "fixture.write", Operation: pngstore.WriteOperation, CommandID: "template-create-" + key, ExpectedRevision: graph["revision"].(string), Mutations: []pngstore.Mutation{{Family: "business:job", Key: key, Data: map[string]interface{}{"id": key, "account_id": scope.AccountID, "name": key}}}}
	exchange := pngFixtureCall(t, handle, config, authority.domain, request, "command", "fixture-human")
	pngFixtureFinish(t, config, authority.domain, exchange, true)
}
func pngTemplateQuery(scope engine.DomainScope, key string) pngstore.Request {
	return pngstore.Request{ContractRevision: pngstore.Revision, Scope: scope, Action: "fixture.read", Query: pngstore.Query{Family: "business:job", Key: key, Limit: 1, Fields: []string{"id", "account_id", "name"}}}
}
func pngTemplateRead(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, scope engine.DomainScope, key string) {
	exchange := pngFixtureCall(t, handle, config, authority, pngTemplateQuery(scope, key), "read", "fixture-member")
	rows := exchange.body["records"].([]interface{})
	if len(rows) != 1 {
		t.Fatal("paired future-node read template was not inherited")
	}
	pngFixtureFinish(t, config, authority, exchange, true)
}
func pngTemplateDeny(t *testing.T, handle *Handle, authority *pngFixtureAuthority, scope engine.DomainScope, key string) {
	input := pngFixtureInput(t, pngTemplateQuery(scope, key), "read")
	intent := pngFixtureResolve(t, handle, input)
	proof := authority.issue(intent, "admission", nil, "fixture-member")
	if _, err := handle.DomainCall(domainFixtureJSON(t, DomainRequest{DomainInput: input, RequestID: "revoked-denied", Proof: proof})); err == nil {
		t.Fatal("revoked existing or future read template granted disclosure")
	}
}
