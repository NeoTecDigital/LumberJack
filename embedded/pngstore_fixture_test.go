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

func pngFixtureConfig() DomainConfig {
	config := domainFixtureConfig()
	config.IntegrationIssuer = "channel-integration:fixture"
	config.MaxFields = 150
	config.MaxResources = 200
	config.MaxLeases = 200
	owned := &config.Scopes[0]
	owned.Bounds.MaxChanges = 20
	owned.Bounds.MaxNodes = 200
	owned.Bounds.MaxReceipts = 50
	owned.Layout.Kinds["png_record"] = "fixture.png_record"
	for _, field := range []string{"pngKey", "pngFamily", "pngData", "pngVersion"} {
		owned.Layout.Fields[field] = "fixture." + field
	}
	for _, operation := range []string{"png.store.read", pngstore.WriteOperation} {
		target := "/manifest/native-store/read"
		if operation == pngstore.WriteOperation {
			target = "/manifest/native-store/execute"
		}
		owned.Layout.Routes[operation] = engine.DomainRoute{Method: "POST", Target: target}
		owned.Layout.Profiles[operation] = map[string][]string{"root": append([]string{"id"}, pngFixtureDynamicFields()...), "png_record": append([]string{"id", "pngKey", "pngFamily", "pngData", "pngVersion"}, pngFixtureDynamicFields()...)}
	}
	return config
}
func pngFixtureACL() map[string]interface{} {
	fields := []string{"id", "children", "pngKey", "pngFamily", "pngData", "pngVersion", "reference"}
	fields = append(fields, pngFixtureDynamicFields()...)
	grant := func(selected []string) map[string]interface{} {
		return map[string]interface{}{"read": map[string]interface{}{"fields": selected, "reference": true}, "png.store.read": map[string]interface{}{"fields": selected, "reference": true}, pngstore.WriteOperation: map[string]interface{}{"fields": selected, "reference": true, "createKinds": []string{"png_record"}}}
	}
	limited := []string{"id", "pngKey", "pngFamily", "pngData", "pngVersion", "data.id", "data.account_id", "data.name", "family.business:job"}
	return map[string]interface{}{"contractRevision": "lj.domain.acl/1", "principals": map[string]interface{}{"fixture-human": grant(fields), "fixture-limited": grant(limited), "associate:fixture": grant(fields)}}
}
func provisionPNGFixture(t *testing.T, config DomainConfig) string {
	t.Helper()
	parent := t.TempDir()
	directory := filepath.Join(parent, "native")
	spec := pngFixtureOwnerSpec(config, directory)
	path := filepath.Join(parent, "owner.json")
	if err := os.WriteFile(path, domainFixtureJSON(t, spec), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/go", "test", "../internal", "-run", "^TestDomainFixtureProvisionOwner$", "-count=1", "-args", "-domain-fixture-owner-spec="+path)
	cmd.Env = domainFixtureGoEnvironment(t, parent)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("synthetic native owner provisioning: %v\n%s", err, output)
	}
	return directory
}
func openPNGFixture(t *testing.T, directory string, config DomainConfig) *Handle {
	t.Helper()
	handle, err := OpenPath("fixture", directory, "fixture", "fixture-private-owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = handle.ConfigureDomain(domainFixtureJSON(t, config)); err != nil {
		t.Fatal(err)
	}
	return handle
}
func closePNGFixture(t *testing.T, handle *Handle) {
	t.Helper()
	runtime := handle.runtime
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	registryMu.Lock()
	closed := runtime.refs == 0 && registry[runtime.path] == nil
	registryMu.Unlock()
	if !closed {
		t.Fatal("full native stop retained an uncompleted runtime or lock")
	}
}

func pngFixtureOwnerSpec(config DomainConfig, directory string) map[string]interface{} {
	acl := pngFixtureACL()
	acl["createACLs"] = map[string]interface{}{"png_record": pngFixtureACL()}
	record := func(id, kind, parent string, metadata map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"id": id, "name": id, "kind": kind, "parentId": parent, "metadata": metadata}
	}
	records := []interface{}{record("account-root", "account", "forest", nil), record("product-root", "fixture.root", "account-root", map[string]interface{}{"fixture.acl": acl})}
	return map[string]interface{}{"directory": directory, "name": "fixture", "forestId": "forest", "forestName": "synthetic PNG test forest", "config": config, "records": records}
}

func pngFixtureDynamicFields() []string {
	fields := []string{"reference"}
	for _, field := range []string{"id", "account_id", "name", "secret", "phone", "type", "state", "attempts", "claim_token", "claim_epoch", "revision", "title", "created_at", "full_name", "attributes", "operation", "fingerprint", "connector_id", "message", "attempt", "outcome", "conflicts", "run", "run_id", "record", "resolved_record", "status", "before", "applied_data", "applied_version", "applied_canonical_id", "source", "canonical_id", "entity_type", "source_hash", "approved_by", "authorization_revision", "approval_ref", "compensated"} {
		fields = append(fields, "data."+field)
	}
	for _, family := range []string{"business:job", "business:associate", "jobs", "inbox", "native.command_receipt", "resource:role", "migration.run", "migration.observation", "migration.alias"} {
		fields = append(fields, "family."+family)
	}
	return fields
}
