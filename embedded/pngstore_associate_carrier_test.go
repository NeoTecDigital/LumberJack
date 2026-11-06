// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"context"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Real native staged writer/reopens; current authority and source records are LABELLED fixtures.
func TestPNGAssociateCarrierActualAtomicMappingRolesRetryAndTwoReopens(t *testing.T) {
	config := pngAssociateConfig()
	authority := pngFixtureVerifier(t, &config)
	directory := pngAssociateProvision(t, config, "")
	handle := openPNGFixture(t, directory, config)
	request := pngAssociateCreate(pngAssociateRevision(t, handle, config, authority))
	created := pngFixtureCall(t, handle, config, authority, request, "command", "fixture-human")
	first := pngAssociateRecord(t, created)
	if created.received.Pair == nil || first.NativeID == first.Key || first.Family != pngstore.AssociateFamily {
		t.Fatal("actual single-node canonical/native pair absent")
	}
	pngFixtureFinish(t, config, authority, created, true)
	retry := pngFixtureCall(t, handle, config, authority, request, "command", "fixture-human")
	if pngAssociateRecord(t, retry).NativeID != first.NativeID || retry.body["receipt"].(map[string]interface{})["status"] != "replayed" {
		t.Fatal("same native command retried as a second creation")
	}
	pngFixtureFinish(t, config, authority, retry, true)
	pngAssociateAssertGraph(t, pngAssociateGraph(t, handle, config, authority), first.NativeID, "Canonical fixture", 0)
	pngAssociateAttachRoles(t, handle, config, authority, first.NativeID)
	pngAssociateDeniedExisting(t, handle, config, authority, first)
	changed := pngAssociatePatch(t, handle, config, authority, first)
	pngAssociateAssertGraph(t, pngAssociateGraph(t, handle, config, authority), first.NativeID, "Changed fixture", 2)
	closePNGFixture(t, handle)
	for cycle := 0; cycle < 2; cycle++ {
		handle = openPNGFixture(t, directory, config)
		pngAssociateAssertGraph(t, pngAssociateGraph(t, handle, config, authority), first.NativeID, "Changed fixture", 2)
		pngAssociateAssertBusiness(t, handle, config, authority, changed)
		closePNGFixture(t, handle)
	}
}

func TestPNGAssociateCarrierActualMissingCreateProjectionTemplateOrCurrentRightsDenies(t *testing.T) {
	for _, mode := range []string{"no-create", "no-projection", "no-template", "no-current"} {
		t.Run(mode, func(t *testing.T) { pngAssociateDeniedCreation(t, mode) })
	}
}

func pngAssociateDeniedCreation(t *testing.T, mode string) {
	config := pngAssociateConfig()
	authority := pngFixtureVerifier(t, &config)
	handle := openPNGFixture(t, pngAssociateProvision(t, config, mode), config)
	request := pngAssociateCreate(pngAssociateRevision(t, handle, config, authority))
	input := pngFixtureInput(t, request, "command")
	intent := pngFixtureResolve(t, handle, input)
	principal := "fixture-human"
	if mode == "no-create" {
		principal = "fixture-limited"
	}
	proof := authority.issue(intent, "admission", nil, principal)
	if mode == "no-current" {
		authority.revoke()
	}
	if _, err := handle.DomainCall(domainFixtureJSON(t, DomainRequest{DomainInput: input, RequestID: "carrier-denied", Proof: proof})); err == nil {
		t.Fatal("missing Associate-specific current creation authority succeeded")
	}
	authority.mu.Lock()
	authority.current = true
	authority.mu.Unlock()
	if len(pngAssociateGraph(t, handle, config, authority)["associates"].([]interface{})) != 0 {
		t.Fatal("denied mixed import left an Associate behind")
	}
	for _, family := range []string{pngstore.AssociateFamily, "migration.alias", "migration.observation"} {
		read := pngFixtureRead(t, handle, config, authority, family, "", []string{"id", "account_id"})
		if len(read.body["records"].([]interface{})) != 0 {
			t.Fatal("denied mixed import partially persisted business/evidence rows")
		}
		pngFixtureFinish(t, config, authority, read, true)
	}
	closePNGFixture(t, handle)
}

func TestPNGAssociateCarrierActualLegacyGenericRefusalSurvivesReopen(t *testing.T) {
	config := pngAssociateConfig()
	policy := config.Scopes[0].Layout.AssociateCarrier
	config.Scopes[0].Layout.AssociateCarrier = nil
	authority := pngFixtureVerifier(t, &config)
	directory := pngAssociateProvision(t, config, "")
	handle := openPNGFixture(t, directory, config)
	request := pngAssociateCreate(pngAssociateRevision(t, handle, config, authority))
	request.Mutations = request.Mutations[:1]
	created := pngFixtureCall(t, handle, config, authority, request, "command", "fixture-human")
	first := pngAssociateRecord(t, created)
	pngFixtureFinish(t, config, authority, created, true)
	closePNGFixture(t, handle)
	config.Scopes[0].Layout.AssociateCarrier = policy
	handle = openPNGFixture(t, directory, config)
	read := pngstore.Request{ContractRevision: pngstore.Revision, Scope: request.Scope, Action: "migration.apply.associate", Query: pngstore.Query{Family: "migration.alias", Limit: 1, Fields: []string{"id"}}}
	if _, err := handle.DomainResolve(domainFixtureJSON(t, pngFixtureInput(t, read, "read"))); err == nil {
		t.Fatal("generic Associate was certified through an unrelated alias scan")
	}
	if len(pngAssociateGraph(t, handle, config, authority)["associates"].([]interface{})) != 0 {
		t.Fatal("legacy row was silently promoted or given a second graph node")
	}
	closePNGFixture(t, handle)
	config.Scopes[0].Layout.AssociateCarrier = nil
	handle = openPNGFixture(t, directory, config)
	pngAssociateAssertBusiness(t, handle, config, authority, first)
	closePNGFixture(t, handle)
}

func pngAssociateConfig() DomainConfig {
	config := pngFixtureConfig()
	owned := &config.Scopes[0]
	null := ""
	owned.Layout.AssociateCarrier = &engine.DomainAssociateCarrierPolicy{ContractRevision: pngstore.AssociateCarrierRevision, Family: pngstore.AssociateFamily, NativeKind: "associate", LabelField: "full_name", NullLabel: &null, InitialRoleIDs: []string{}}
	owned.Layout.Routes["read"] = engine.DomainRoute{Method: "POST", Target: "/manifest/read"}
	owned.Layout.Routes["associate.role.attach"] = engine.DomainRoute{Method: "POST", Target: "/manifest/associate.role.attach"}
	owned.Layout.Profiles["associate.role.attach"] = map[string][]string{"root": {"id"}, "associate": {"id", "roleIds", "reference"}, "role": {"id", "reference"}}
	for _, operation := range []string{"png.store.read", pngstore.WriteOperation} {
		owned.Layout.Profiles[operation]["associate"] = pngAssociateStoreFields()
	}
	owned.Layout.Profiles[pngstore.WriteOperation]["root"] = append(owned.Layout.Profiles[pngstore.WriteOperation]["root"], "accountId", "label", "roleIds")
	return config
}

func pngAssociateStoreFields() []string {
	return []string{"id", "pngKey", "pngFamily", "pngData", "pngVersion", "accountId", "label", "roleIds", "reference", "family.business:associate", "data.id", "data.account_id", "data.full_name", "data.phone"}
}

func pngAssociateACL(config DomainConfig, kind, mode string) map[string]interface{} {
	fields := append([]string{"id", "children", "pngKey", "pngFamily", "pngData", "pngVersion", "accountId", "label", "roleIds"}, pngFixtureDynamicFields()...)
	create := []string{}
	if kind == "root" {
		create = []string{"png_record", "associate"}
	}
	grants := map[string]interface{}{"read": map[string]interface{}{"fields": domainFixtureReadFields()[kind], "reference": true},
		"png.store.read":        map[string]interface{}{"fields": fields, "reference": true},
		pngstore.WriteOperation: map[string]interface{}{"fields": fields, "reference": true, "createKinds": create},
		"associate.role.attach": map[string]interface{}{"fields": []string{"id", "roleIds", "reference"}, "reference": true}}
	if kind == "associate" {
		grants["png.store.read"] = map[string]interface{}{"fields": pngAssociateStoreFields(), "reference": true}
		grants[pngstore.WriteOperation] = map[string]interface{}{"fields": pngAssociateStoreFields(), "reference": true}
	}
	principals := map[string]interface{}{"fixture-human": grants}
	if kind == "root" {
		principals["fixture-limited"] = map[string]interface{}{pngstore.WriteOperation: map[string]interface{}{"fields": fields, "reference": true, "createKinds": []string{"png_record"}}}
	}
	if mode == "no-projection" && kind == "root" {
		grants[pngstore.WriteOperation] = map[string]interface{}{"fields": append([]string{"id", "children", "pngKey", "pngFamily", "pngData", "pngVersion"}, pngFixtureDynamicFields()...), "reference": true, "createKinds": create}
	}
	return map[string]interface{}{"contractRevision": "lj.domain.acl/1", "principals": principals}
}

func pngAssociateOwnerSpec(config DomainConfig, directory, mode string) map[string]interface{} {
	spec := pngFixtureOwnerSpec(config, directory)
	rows := spec["records"].([]interface{})
	acl := pngAssociateACL(config, "root", mode)
	templates := map[string]interface{}{"png_record": pngFixtureACL()}
	if mode != "no-template" {
		templates["associate"] = pngAssociateACL(config, "associate", "")
	}
	acl["createACLs"] = templates
	rows[1].(map[string]interface{})["metadata"] = map[string]interface{}{config.ACLMetadataKey: acl}
	for _, id := range []string{"role-a", "role-b"} {
		metadata := map[string]interface{}{config.ACLMetadataKey: pngAssociateACL(config, "role", ""), "fixture.accountId": "fixture-account", "fixture.label": id, "fixture.requirementIds": []string{}, "fixture.functionIds": []string{}}
		rows = append(rows, map[string]interface{}{"id": id, "name": id, "kind": "fixture.role", "parentId": "product-root", "metadata": metadata})
	}
	spec["records"] = rows
	return spec
}

func pngAssociateProvision(t *testing.T, config DomainConfig, mode string) string {
	t.Helper()
	parent := t.TempDir()
	directory, path := filepath.Join(parent, "native"), filepath.Join(parent, "associate-owner.json")
	if err := os.WriteFile(path, domainFixtureJSON(t, pngAssociateOwnerSpec(config, directory, mode)), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/go", "test", "../internal", "-run", "^TestDomainFixtureProvisionOwner$", "-count=1", "-args", "-domain-fixture-owner-spec="+path)
	command.Env = domainFixtureGoEnvironment(t, parent)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("LABELLED actual native carrier fixture provisioning: %v\n%s", err, output)
	}
	return directory
}

func pngAssociateCreate(revision string) pngstore.Request {
	mutation := pngstore.Mutation{Family: pngstore.AssociateFamily, Key: "canonical-associate", Data: map[string]interface{}{"id": "canonical-associate", "account_id": "fixture-account", "full_name": "Canonical fixture", "phone": "+15550002000"}}
	alias := pngstore.Mutation{Family: "migration.alias", Key: "canonical-source-alias", Data: map[string]interface{}{"id": "canonical-source-alias", "account_id": "fixture-account", "canonical_id": mutation.Key}}
	observation := pngstore.Mutation{Family: "migration.observation", Key: "canonical-observation", Data: map[string]interface{}{"id": "canonical-observation", "account_id": "fixture-account", "status": "applied", "applied_canonical_id": mutation.Key}}
	return pngstore.Request{ContractRevision: pngstore.Revision, Scope: engine.DomainScope{AccountID: "fixture-account", Product: "manifest"}, Action: "migration.apply.associate", Operation: pngstore.WriteOperation, CommandID: "associate-import-command", ExpectedRevision: revision, Mutations: []pngstore.Mutation{mutation, alias, observation}}
}

func pngAssociateRevision(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority) string {
	read := pngFixtureRead(t, handle, config, authority, pngstore.AssociateFamily, "canonical-associate", []string{"id", "account_id", "full_name", "phone"})
	revision := read.body["revision"].(string)
	pngFixtureFinish(t, config, authority, read, true)
	return revision
}

func pngAssociateRecord(t *testing.T, exchange pngFixtureExchange) pngstore.Record {
	t.Helper()
	var result struct {
		Records []pngstore.Record `json:"records"`
		Result  interface{}       `json:"result"`
	}
	if err := engine.DecodeDomainJSON(domainFixtureJSON(t, exchange.body["data"]), &result); err != nil {
		t.Fatal(err)
	}
	for _, record := range result.Records {
		if record.Family == pngstore.AssociateFamily {
			return record
		}
	}
	t.Fatal("retained canonical Associate result absent")
	return pngstore.Record{}
}

func pngAssociateGraph(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority) map[string]interface{} {
	body := map[string]interface{}{"contractRevision": "manifest-associates/0.1", "scope": engine.DomainScope{AccountID: "fixture-account", Product: "manifest"}}
	exchange := pngActualGraphCall(t, handle, config, authority, body, "read", "/manifest/read")
	graph := exchange.body["graph"].(map[string]interface{})
	pngFixtureFinish(t, config, authority, exchange, true)
	return graph
}

func pngAssociateAssertGraph(t *testing.T, graph map[string]interface{}, id, label string, roles int) {
	t.Helper()
	rows := graph["associates"].([]interface{})
	if len(rows) != 1 {
		t.Fatal("graph did not contain exactly one actual Associate")
	}
	associate := rows[0].(map[string]interface{})
	if associate["id"] != id || associate["label"] != label || len(associate["roleIds"].([]interface{})) != roles {
		t.Fatal("native graph lost canonical linkage/label/stacked Roles")
	}
}

func pngAssociateAttachRoles(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, id string) {
	for _, role := range []string{"role-a", "role-b"} {
		graph := pngAssociateGraph(t, handle, config, authority)
		body := map[string]interface{}{"contractRevision": "manifest-associates/0.1", "scope": engine.DomainScope{AccountID: "fixture-account", Product: "manifest"}, "commandId": "attach-" + role, "expectedRevision": graph["revision"], "operation": "associate.role.attach", "payload": map[string]interface{}{"associateId": id, "roleId": role}}
		exchange := pngActualGraphCall(t, handle, config, authority, body, "command", "/manifest/associate.role.attach")
		pngFixtureFinish(t, config, authority, exchange, true)
	}
}

func pngAssociatePatch(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, current pngstore.Record) pngstore.Record {
	revision := pngAssociateRevision(t, handle, config, authority)
	request := pngAssociateCreate(revision)
	request.CommandID = "associate-business-patch"
	request.Mutations = []pngstore.Mutation{{Family: current.Family, Key: current.Key, NativeID: current.NativeID, ExpectedVersion: current.Version, Patch: true, Data: map[string]interface{}{"id": current.Key, "account_id": "fixture-account", "full_name": "Changed fixture"}}}
	changed := pngFixtureCall(t, handle, config, authority, request, "command", "fixture-human")
	result := pngAssociateRecord(t, changed)
	if result.NativeID != current.NativeID || result.Version == current.Version {
		t.Fatal("business patch replaced native identity or failed business CAS")
	}
	pngFixtureFinish(t, config, authority, changed, true)
	return result
}

func pngAssociateDeniedExisting(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, current pngstore.Record) {
	request := pngAssociateCreate(pngAssociateRevision(t, handle, config, authority))
	request.CommandID = "limited-cannot-patch-associate"
	request.Mutations = []pngstore.Mutation{{Family: current.Family, Key: current.Key, NativeID: current.NativeID, ExpectedVersion: current.Version, Patch: true, Data: map[string]interface{}{"phone": "+15550003000"}}}
	input := pngFixtureInput(t, request, "command")
	intent := pngFixtureResolve(t, handle, input)
	proof := authority.issue(intent, "admission", nil, "fixture-limited")
	if _, err := handle.DomainCall(domainFixtureJSON(t, DomainRequest{DomainInput: input, RequestID: "existing-associate-denied", Proof: proof})); err == nil {
		t.Fatal("generic png_record action grants authorized an existing Associate")
	}
}

func pngAssociateAssertBusiness(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, expected pngstore.Record) {
	read := pngFixtureRead(t, handle, config, authority, pngstore.AssociateFamily, expected.Key, []string{"id", "account_id", "full_name", "phone"})
	var rows []pngstore.Record
	if engine.DecodeDomainJSON(domainFixtureJSON(t, read.body["records"]), &rows) != nil || len(rows) != 1 || rows[0].NativeID != expected.NativeID || rows[0].Version != expected.Version || rows[0].Data["phone"] != "+15550002000" {
		t.Fatal("native reopen lost canonical identity/version or preserved hidden business field")
	}
	pngFixtureFinish(t, config, authority, read, true)
}
