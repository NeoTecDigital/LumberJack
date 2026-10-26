// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"testing"
)

func TestPNGActualStagedPairAndTwoFullReopens(t *testing.T) {
	config := pngFixtureConfig()
	authority := pngFixtureVerifier(t, &config)
	directory := provisionPNGFixture(t, config)
	handle := openPNGFixture(t, directory, config)
	empty := pngFixtureRead(t, handle, config, authority, "business:job", "job-1", []string{"id", "account_id", "name", "secret"})
	revision := empty.body["revision"].(string)
	pngFixtureFinish(t, config, authority, empty, false)
	request := pngFixtureCreate(revision)
	created := pngFixtureCall(t, handle, config, authority, request, "command", "fixture-human")
	first := pngFixtureRecord(t, created)
	if created.received.Pair == nil || created.received.Pair.Sequence == 0 || first.NativeID == first.Key {
		t.Fatal("actual paired native alias absent")
	}
	pngFixtureFinish(t, config, authority, created, true)
	closePNGFixture(t, handle)
	handle = openPNGFixture(t, directory, config)
	history := pngFixtureRead(t, handle, config, authority, "native.command_receipt", request.CommandID, []string{"id", "account_id", "name"})
	retained := pngFixtureRecord(t, history)
	if retained.NativeID != first.NativeID || retained.Version != first.Version || retained.Data["secret"] != nil {
		t.Fatal("restart retained history lost alias/version or leaked masked field")
	}
	pngFixtureFinish(t, config, authority, history, false)
	current := pngFixtureRead(t, handle, config, authority, "business:job", "job-1", []string{"id", "account_id", "name", "secret"})
	revision = current.body["revision"].(string)
	pngFixtureFinish(t, config, authority, current, false)
	patch := pngFixturePatch(revision, first)
	changed := pngFixtureCall(t, handle, config, authority, patch, "command", "fixture-human")
	second := pngFixtureRecord(t, changed)
	if second.Version == first.Version || second.Data["secret"] != nil {
		t.Fatal("patch CAS version or changed-field disclosure failed")
	}
	pngFixtureFinish(t, config, authority, changed, true)
	closePNGFixture(t, handle)
	handle = openPNGFixture(t, directory, config)
	check := pngFixtureRead(t, handle, config, authority, "business:job", "job-1", []string{"id", "account_id", "name", "secret"})
	assertPNGFinal(t, check, first.NativeID, second.Version)
	pngFixtureFinish(t, config, authority, check, true)
	closePNGFixture(t, handle)
	if authority.acceptanceCount() < 9 {
		t.Fatal("actual exact current native callback was not invoked at admission/handoff")
	}
}
func pngFixtureCreate(revision string) pngstore.Request {
	return pngstore.Request{ContractRevision: pngstore.Revision, Scope: engine.DomainScope{AccountID: "fixture-account", Product: "manifest"}, Action: "fixture.write", Operation: pngstore.WriteOperation, CommandID: "png-fixture-create", ExpectedRevision: revision, Mutations: []pngstore.Mutation{{Family: "business:job", Key: "job-1", Data: map[string]interface{}{"id": "job-1", "account_id": "fixture-account", "name": "retained", "secret": "preserve-hidden"}}}}
}
func pngFixturePatch(revision string, current pngstore.Record) pngstore.Request {
	request := pngFixtureCreate(revision)
	request.CommandID = "png-fixture-patch"
	request.Mutations = []pngstore.Mutation{{Family: current.Family, Key: current.Key, NativeID: current.NativeID, ExpectedVersion: current.Version, Patch: true, Data: map[string]interface{}{"id": current.Key, "account_id": "fixture-account", "name": "updated"}}}
	return request
}
func assertPNGFinal(t *testing.T, exchange pngFixtureExchange, id, version string) {
	t.Helper()
	raw := domainFixtureJSON(t, exchange.body["records"])
	var rows []pngstore.Record
	if err := engine.DecodeDomainJSON(raw, &rows); err != nil || len(rows) != 1 {
		t.Fatal("reopened native record missing", err)
	}
	if rows[0].NativeID != id || rows[0].Version != version || rows[0].Data["secret"] != "preserve-hidden" || rows[0].Data["name"] != "updated" {
		t.Fatal("two full native reopens lost retained patch/hidden field/explicit alias")
	}
}
func TestPNGActualACLAndRevokedCurrentProofDeny(t *testing.T) {
	config := pngFixtureConfig()
	authority := pngFixtureVerifier(t, &config)
	handle := openPNGFixture(t, provisionPNGFixture(t, config), config)
	empty := pngFixtureRead(t, handle, config, authority, "business:job", "job-1", []string{"id", "account_id", "name"})
	revision := empty.body["revision"].(string)
	pngFixtureFinish(t, config, authority, empty, false)
	created := pngFixtureCall(t, handle, config, authority, pngFixtureCreate(revision), "command", "fixture-human")
	pngFixtureFinish(t, config, authority, created, false)
	read := pngstore.Request{ContractRevision: pngstore.Revision, Scope: engine.DomainScope{AccountID: "fixture-account", Product: "manifest"}, Action: "fixture.read", Query: pngstore.Query{Family: "business:job", Key: "job-1", Limit: 1, Fields: []string{"secret"}}}
	input := pngFixtureInput(t, read, "read")
	intent := pngFixtureResolve(t, handle, input)
	proof := authority.issue(intent, "admission", nil, "fixture-limited")
	if _, err := handle.DomainCall(domainFixtureJSON(t, DomainRequest{DomainInput: input, RequestID: "acl-denied", Proof: proof})); err == nil {
		t.Fatal("pngData-only native grant bypassed secret field ACL")
	}
	if _, err := handle.DomainCall(domainFixtureJSON(t, DomainRequest{DomainInput: input, RequestID: "forged", Proof: "unissued_metadata"})); err == nil {
		t.Fatal("unissued native proof was accepted")
	}
	active := pngFixtureRead(t, handle, config, authority, "business:job", "job-1", []string{"id", "account_id", "name"})
	authority.revoke()
	handoff := domainFixtureControl(config, active.begin, "handoff")
	handoff.Proof = authority.issue(active.intent, "handoff", &active.begin.Lease, "fixture-human")
	if _, err := DomainControlCall(domainFixtureJSON(t, handoff)); err == nil {
		t.Fatal("revoked current-rights callback permitted disclosure")
	}
	pngFixtureFinish(t, config, authority, active, false)
	closePNGFixture(t, handle)
}
