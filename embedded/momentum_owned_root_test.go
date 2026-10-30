// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/products/momentum"
)

func ownedRootSpec(t *testing.T, config DomainConfig, acl map[string]interface{}) []byte {
	t.Helper()
	owned := config.Scopes[0]
	return domainFixtureJSON(t, map[string]interface{}{"binding": owned.Binding, "bounds": owned.Bounds,
		"accountKind": "account", "rootKind": owned.Layout.Kinds["root"], "metadata": map[string]interface{}{config.ACLMetadataKey: acl}})
}

func openOwnedRootHandle(t *testing.T, directory string) *Handle {
	t.Helper()
	handle, err := OpenPath("fixture", directory, "fixture", "fixture-private-owner")
	if err != nil {
		t.Fatal(err)
	}
	return handle
}

func provisionOwnedRootOnce(t *testing.T, directory string, body []byte, state string) {
	t.Helper()
	handle := openOwnedRootHandle(t, directory)
	defer handle.Close()
	answer, err := handle.ProvisionOwnedRoot(body)
	if err != nil {
		t.Fatal(err)
	}
	if want := `"state":"` + state + `"`; !containsBytes(answer, want) {
		t.Fatalf("owned root answered %s, want %s", answer, want)
	}
}

func containsBytes(raw []byte, text string) bool { return strings.Contains(string(raw), text) }

func TestMomentumProvisionedRootServesTheWorkspaceAcrossReopens(t *testing.T) {
	config := momentumFixtureConfig()
	momentumFixtureVerifier(t, &config)
	directory := filepath.Join(t.TempDir(), "native")
	body := ownedRootSpec(t, config, momentumFixtureACL(config, true))
	provisionOwnedRootOnce(t, directory, body, "created")
	provisionOwnedRootOnce(t, directory, body, "replayed")
	handle := openMomentumFixture(t, config, directory)
	read := momentumInput(t, "read", "", "", nil)
	before := momentumResult(t, handle, config, read)
	init := momentumInput(t, momentum.Initialize, "initialize-once", before["revision"].(string), map[string]interface{}{"nodeId": config.Scopes[0].Binding.RootID})
	assertMomentumStatus(t, momentumResult(t, handle, config, init), "applied")
	if _, err := handle.ProvisionOwnedRoot(body); err == nil {
		t.Fatal("a domain-configured handle provisioned a root")
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	provisionOwnedRootOnce(t, directory, body, "replayed")
	handle = openMomentumFixture(t, config, directory)
	defer handle.Close()
	if rows := momentumResult(t, handle, config, read)["nodes"].([]interface{}); len(rows) != 9 {
		t.Fatalf("workspace not retained: %d nodes", len(rows))
	}
}

func TestMomentumProvisioningAddsASecondRootToAnExistingForest(t *testing.T) {
	config := momentumFixtureConfig()
	momentumFixtureVerifier(t, &config)
	directory := filepath.Join(t.TempDir(), "native")
	provisionOwnedRootOnce(t, directory, ownedRootSpec(t, config, momentumFixtureACL(config, true)), "created")
	handle := openMomentumFixture(t, config, directory)
	read := momentumInput(t, "read", "", "", nil)
	before := momentumResult(t, handle, config, read)
	init := momentumInput(t, momentum.Initialize, "initialize-first", before["revision"].(string), map[string]interface{}{"nodeId": config.Scopes[0].Binding.RootID})
	assertMomentumStatus(t, momentumResult(t, handle, config, init), "applied")
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	second := config
	second.Scopes = append(second.Scopes[:0:0], config.Scopes[0])
	owned := &second.Scopes[0]
	owned.Binding.ScopeID, owned.Binding.AccountID = "second-scope", "second-account"
	owned.Binding.AccountRootID, owned.Binding.RootID = "second-account-root", "second-root"
	provisionOwnedRootOnce(t, directory, ownedRootSpec(t, second, momentumFixtureACL(config, true)), "created")
	both := config
	both.Scopes = append(append(both.Scopes[:0:0], config.Scopes[0]), second.Scopes[0])
	handle = openMomentumFixture(t, both, directory)
	defer handle.Close()
	if rows := momentumResult(t, handle, both, read)["nodes"].([]interface{}); len(rows) != 9 {
		t.Fatalf("first workspace changed by the second root: %d nodes", len(rows))
	}
}

func TestMomentumOwnedRootRefusesConflictsAndOtherProducts(t *testing.T) {
	config := momentumFixtureConfig()
	directory := filepath.Join(t.TempDir(), "native")
	provisionOwnedRootOnce(t, directory, ownedRootSpec(t, config, momentumFixtureACL(config, true)), "created")
	handle := openOwnedRootHandle(t, directory)
	defer handle.Close()
	if _, err := handle.ProvisionOwnedRoot(ownedRootSpec(t, config, momentumFixtureACL(config, false))); err == nil {
		t.Fatal("a different ACL replayed over an existing root")
	}
	moved := config
	moved.Scopes = append(moved.Scopes[:0:0], config.Scopes[0])
	moved.Scopes[0].Binding.AccountRootID = "another-account-root"
	if _, err := handle.ProvisionOwnedRoot(ownedRootSpec(t, moved, momentumFixtureACL(config, true))); err == nil {
		t.Fatal("an existing root was adopted under another account container")
	}
	adopted := config
	adopted.Scopes = append(adopted.Scopes[:0:0], config.Scopes[0])
	adopted.Scopes[0].Binding.RootID = "another-root"
	if _, err := handle.ProvisionOwnedRoot(ownedRootSpec(t, adopted, momentumFixtureACL(config, true))); err == nil {
		t.Fatal("an existing account container was adopted by another root")
	}
	manifest := config
	manifest.Scopes = append(manifest.Scopes[:0:0], config.Scopes[0])
	manifest.Scopes[0].Binding.ProductID = "manifest"
	manifest.Scopes[0].Binding.RootID, manifest.Scopes[0].Binding.AccountRootID = "manifest-root", "manifest-account-root"
	if _, err := handle.ProvisionOwnedRoot(ownedRootSpec(t, manifest, momentumFixtureACL(config, true))); err == nil {
		t.Fatal("this operation provisioned a Manifest root; enrollment owns those")
	}
	if _, err := handle.ProvisionOwnedRoot([]byte(`{"binding":{},"unknown":true}`)); err == nil {
		t.Fatal("an open grammar was accepted")
	}
}
