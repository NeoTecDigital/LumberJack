// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"testing"
)

func TestPNGActualEnrollThenRoleDefineReloadAndRestart(t *testing.T) {
	if *pngProfileArtifact == "" {
		t.Skip("explicit protected profile artifact required")
	}
	config := pngProtectedConfig(t, *pngProfileArtifact)
	scope := engine.DomainScope{AccountID: "actual-new-organization", Product: "manifest"}
	input := engine.EnrollmentInput{ContractRevision: engine.EnrollmentProofRevision, RequestID: "actual-enrollment-request", Proof: "actual_enrollment_admission", Request: engine.EnrollmentRequest{ContractRevision: engine.EnrollmentRevision, Scope: scope, CommandID: "actual-enrollment-command", ExpectedRevision: "absent", Operation: engine.EnrollmentProvision, ProfileRef: config.ProvisioningProfile.ProfileRef}}
	authority := pngEnrolledVerifier(t, &config, input)
	directory := t.TempDir()
	handle := openPNGFixture(t, directory, config)
	begin := pngActualEnrollment(t, handle, config, input, authority)
	if begin.Lease.Binding.RootID == scope.AccountID || begin.Lease.Binding.RootID == "" {
		t.Fatal("native root identity was inferred from canonical org")
	}
	graph := pngActualGraphRead(t, handle, config, authority.domain, scope)
	revision := graph["revision"].(string)
	pngActualRoleDefine(t, handle, config, authority.domain, scope, revision)
	assertPNGRole(t, pngActualGraphRead(t, handle, config, authority.domain, scope))
	closePNGFixture(t, handle)
	handle = openPNGFixture(t, directory, config)
	assertPNGRole(t, pngActualGraphRead(t, handle, config, authority.domain, scope))
	closePNGFixture(t, handle)
}
func pngActualEnrollment(t *testing.T, handle *Handle, config DomainConfig, input engine.EnrollmentInput, authority *pngEnrolledAuthority) engine.DomainBegin {
	raw, err := handle.DomainEnrollJSON(domainFixtureJSON(t, input))
	var begin engine.DomainBegin
	if err != nil || engine.DecodeDomainJSON(raw, &begin) != nil {
		t.Fatal("actual owner enrollment failed", err)
	}
	authority.domain.mu.Lock()
	authority.lease = &begin.Lease
	authority.domain.mu.Unlock()
	_ = domainFixtureControlCall(t, domainFixtureControl(config, begin, "adopt"))
	var received engine.DomainReceived
	if err = engine.DecodeDomainJSON(domainFixtureControlCall(t, domainFixtureControl(config, begin, "receive")), &received); err != nil || received.Pair == nil {
		t.Fatal("actual paired enrollment receipt absent", err)
	}
	handoff := domainFixtureControl(config, begin, "handoff")
	handoff.Proof = input.Proof + "_handoff"
	var permit engine.DomainPermit
	if err = engine.DecodeDomainJSON(domainFixtureControlCall(t, handoff), &permit); err != nil {
		t.Fatal(err)
	}
	finish := domainFixtureControl(config, begin, "finish")
	finish.ResponseHash, finish.Disposition, finish.PermitID = begin.ResponseHash, "handed-off", permit.PermitID
	_ = domainFixtureControlCall(t, finish)
	return begin
}
func pngActualGraphRead(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, scope engine.DomainScope) map[string]interface{} {
	body := map[string]interface{}{"contractRevision": "manifest-associates/0.1", "scope": scope}
	exchange := pngActualGraphCall(t, handle, config, authority, body, "read", "/manifest/read")
	graph, ok := exchange.body["graph"].(map[string]interface{})
	if !ok {
		t.Fatal("actual graph result absent")
	}
	pngFixtureFinish(t, config, authority, exchange, true)
	return graph
}
func pngActualRoleDefine(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, scope engine.DomainScope, revision string) {
	body := map[string]interface{}{"contractRevision": "manifest-associates/0.1", "scope": scope, "commandId": "actual-define-role", "expectedRevision": revision, "operation": "role.define", "payload": map[string]interface{}{"label": "Actual enrolled role"}}
	exchange := pngActualGraphCall(t, handle, config, authority, body, "command", "/manifest/role.define")
	if exchange.received.Pair == nil || exchange.body["data"] != nil {
		t.Fatal("graph paired receipt grammar changed or absent")
	}
	pngFixtureFinish(t, config, authority, exchange, true)
}
func pngActualGraphCall(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, body map[string]interface{}, mode, target string) pngFixtureExchange {
	input := DomainInput{Mode: mode, Method: "POST", Target: target, Body: domainFixtureJSON(t, body)}
	intent := pngFixtureResolve(t, handle, input)
	proof := authority.issue(intent, "admission", nil, "fixture-human")
	begin, received := domainFixtureExchange(t, handle, config, DomainRequest{DomainInput: input, RequestID: "actual-graph-request", Proof: proof})
	var result map[string]interface{}
	if err := engine.DecodeDomainJSON(received.Body, &result); err != nil {
		t.Fatal(err)
	}
	return pngFixtureExchange{begin, received, intent, result}
}
func assertPNGRole(t *testing.T, graph map[string]interface{}) {
	roles, ok := graph["roles"].([]interface{})
	if !ok || len(roles) != 1 {
		t.Fatal("retained real role missing")
	}
	role := roles[0].(map[string]interface{})
	if role["label"] != "Actual enrolled role" || role["id"] == "" {
		t.Fatal("actual native role projection changed")
	}
}
