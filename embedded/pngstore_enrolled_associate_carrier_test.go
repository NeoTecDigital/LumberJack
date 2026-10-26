// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"testing"
)

// Requires an explicitly supplied synthetic protected carrier profile, not a
// seeded business-root fixture or a live account/grant change.
func TestPNGActualEnrollmentAssociateCarrierRetryAndTwoReopens(t *testing.T) {
	if *pngProfileArtifact == "" {
		t.Skip("explicit protected synthetic carrier artifact required")
	}
	config := pngProtectedConfig(t, *pngProfileArtifact)
	if config.ProvisioningProfile.Layout.AssociateCarrier == nil {
		t.Skip("supplied protected profile did not explicitly opt into Associate carrier")
	}
	scope := engine.DomainScope{AccountID: "LABELLED-enrolled-carrier-account", Product: "manifest"}
	input := pngEnrolledCarrierInput(config, scope)
	authority := pngEnrolledVerifier(t, &config, input)
	directory := t.TempDir()
	handle := openPNGFixture(t, directory, config)
	pngActualEnrollment(t, handle, config, input, authority)
	before := pngEnrolledCarrierRead(t, handle, config, authority.domain, scope)
	revision := before.body["revision"].(string)
	pngFixtureFinish(t, config, authority.domain, before, true)
	request := pngEnrolledCarrierCreate(scope, revision)
	created := pngFixtureCall(t, handle, config, authority.domain, request, "command", "fixture-human")
	first := pngFixtureRecord(t, created)
	if first.Key != "LABELLED-canonical-associate" || first.NativeID == "" || first.NativeID == first.Key {
		t.Fatal("actual enrollment did not retain distinct canonical/native Associate identities")
	}
	pngFixtureFinish(t, config, authority.domain, created, true)
	retry := pngFixtureCall(t, handle, config, authority.domain, request, "command", "fixture-human")
	if pngFixtureRecord(t, retry).NativeID != first.NativeID || retry.body["receipt"].(map[string]interface{})["status"] != "replayed" {
		t.Fatal("actual enrolled carrier retry duplicated the canonical native node")
	}
	pngFixtureFinish(t, config, authority.domain, retry, true)
	pngAssociateAssertGraph(t, pngActualGraphRead(t, handle, config, authority.domain, scope), first.NativeID, "LABELLED canonical name", 0)
	closePNGFixture(t, handle)
	for cycle := 0; cycle < 2; cycle++ {
		handle = openPNGFixture(t, directory, config)
		pngEnrolledCarrierAssert(t, handle, config, authority.domain, scope, first)
		closePNGFixture(t, handle)
	}
}

func pngEnrolledCarrierInput(config DomainConfig, scope engine.DomainScope) engine.EnrollmentInput {
	request := engine.EnrollmentRequest{ContractRevision: engine.EnrollmentRevision, Scope: scope,
		CommandID: "LABELLED-carrier-enrollment-command", ExpectedRevision: "absent",
		Operation: engine.EnrollmentProvision, ProfileRef: config.ProvisioningProfile.ProfileRef}
	return engine.EnrollmentInput{ContractRevision: engine.EnrollmentProofRevision,
		RequestID: "LABELLED-carrier-enrollment-request", Proof: "LABELLED_carrier_enrollment_proof", Request: request}
}

func pngEnrolledCarrierRead(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, scope engine.DomainScope) pngFixtureExchange {
	t.Helper()
	request := pngstore.Request{ContractRevision: pngstore.Revision, Scope: scope, Action: "LABELLED.carrier.read",
		Query: pngstore.Query{Family: pngstore.AssociateFamily, Key: "LABELLED-canonical-associate",
			Limit: 1, Fields: []string{"id", "account_id", "full_name"}}}
	return pngFixtureCall(t, handle, config, authority, request, "read", "fixture-human")
}

func pngEnrolledCarrierCreate(scope engine.DomainScope, revision string) pngstore.Request {
	mutation := pngstore.Mutation{Family: pngstore.AssociateFamily, Key: "LABELLED-canonical-associate",
		Data: map[string]interface{}{"id": "LABELLED-canonical-associate", "account_id": scope.AccountID, "full_name": "LABELLED canonical name"}}
	return pngstore.Request{ContractRevision: pngstore.Revision, Scope: scope, Action: "migration.apply.associate",
		CommandID: "LABELLED-carrier-import-command", ExpectedRevision: revision, Operation: pngstore.WriteOperation,
		Mutations: []pngstore.Mutation{mutation}}
}

func pngEnrolledCarrierAssert(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, scope engine.DomainScope, first pngstore.Record) {
	t.Helper()
	pngAssociateAssertGraph(t, pngActualGraphRead(t, handle, config, authority, scope), first.NativeID, "LABELLED canonical name", 0)
	exchange := pngEnrolledCarrierRead(t, handle, config, authority, scope)
	var records []pngstore.Record
	if engine.DecodeDomainJSON(domainFixtureJSON(t, exchange.body["records"]), &records) != nil || len(records) != 1 {
		t.Fatal("actual reopened enrollment lost canonical Associate record")
	}
	if records[0].NativeID != first.NativeID || records[0].Version != first.Version || records[0].Data["full_name"] != "LABELLED canonical name" {
		t.Fatal("actual reopened carrier changed identity, version, or original business content")
	}
	pngFixtureFinish(t, config, authority, exchange, true)
}
