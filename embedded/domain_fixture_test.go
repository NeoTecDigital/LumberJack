// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

var domainFixtureOperations = []string{"read", "role.define", "requirement.define", "function.define", "associate.role.attach", "associate.role.detach", "role.requirement.attach", "role.function.attach", "context.record.define", "context.category.define", "item.context.link"}

func domainFixtureConfig() DomainConfig {
	kinds := []string{"root", "associate", "role", "requirement", "function", "record", "category"}
	fields := []string{"accountId", "kind", "label", "roleIds", "requirementIds", "functionIds", "contextLinks", "defaultKey"}
	layout := engine.DomainLayout{Kinds: map[string]string{}, Fields: map[string]string{}, Routes: map[string]engine.DomainRoute{}, Profiles: map[string]map[string][]string{}}
	for _, kind := range kinds {
		layout.Kinds[kind] = "fixture." + kind
	}
	for _, field := range fields {
		layout.Fields[field] = "fixture." + field
	}
	for _, operation := range domainFixtureOperations {
		layout.Routes[operation] = engine.DomainRoute{Method: "POST", Target: "/fixture/" + operation}
		layout.Profiles[operation] = map[string][]string{"root": {"id"}}
	}
	layout.Profiles["read"] = domainFixtureReadFields()
	layout.Profiles["role.define"]["root"] = []string{"id", "children", "accountId", "label", "requirementIds", "functionIds"}
	owned := engine.DomainOwnedScope{Binding: engine.DomainNativeBinding{ProductID: "manifest", BindingRevision: "fixture/v1", ScopeID: "fixture-scope", AccountID: "fixture-account", AccountRootID: "account-root", RootID: "product-root"}, Bounds: engine.DomainBounds{MaxNodes: 50, MaxChanges: 10, MaxReceipts: 10, MaxIdentifierBytes: 200, MaxValueDepth: 32, MaxScopeBytes: 1000000, MaxSnapshotBytes: 2000000}, Layout: layout}
	trust := engine.ActivationConfig{ChannelToken: strings.Repeat("c", 32), Audience: "fixture-native", Issuer: "fixture-owner", TimeoutMs: 5000, MaxProofBytes: 1000, MaxBodyBytes: 100000, MaxResponseBytes: 100000, MaxLifetimeSeconds: 60, SyntheticLoopbackOnly: true}
	return DomainConfig{Trust: trust, HostID: "fixture-host", ControlToken: strings.Repeat("h", 32), OwnerControlToken: strings.Repeat("o", 32), ACLMetadataKey: "fixture.acl", MaxLeases: 10, MaxRetainedEpochs: 1000, MaxResources: 50, MaxFields: 30, MaxRequestBytes: 100000, MaxResponseBytes: 100000, Scopes: []engine.DomainOwnedScope{owned}}
}
func domainFixtureReadFields() map[string][]string {
	return map[string][]string{
		"root":      {"id", "accountId", "revision", "hasMore", "associates", "roles", "requirements", "functions", "records", "categories"},
		"associate": {"id", "accountId", "label", "roleIds"}, "role": {"id", "accountId", "label", "requirementIds", "functionIds", "defaultKey"},
		"requirement": {"id", "accountId", "label", "contextLinks"}, "function": {"id", "accountId", "label", "contextLinks"},
		"record": {"id", "accountId", "kind", "label"}, "category": {"id", "accountId", "kind", "label"},
	}
}
func domainFixtureACL(config DomainConfig, kind string) map[string]interface{} {
	fields := append([]string(nil), domainFixtureReadFields()[kind]...)
	if kind == "root" {
		fields = append(fields, "children", "label", "requirementIds", "functionIds")
	}
	grants := map[string]interface{}{}
	for _, operation := range domainFixtureOperations {
		grants[operation] = map[string]interface{}{"fields": fields, "reference": true, "createKinds": []string{"role"}}
	}
	return map[string]interface{}{"contractRevision": "lj.domain.acl/1", "principals": map[string]interface{}{"fixture-human": grants}}
}
func provisionDomainFixture(t *testing.T, config DomainConfig) string {
	t.Helper()
	parent := t.TempDir()
	directory := filepath.Join(parent, "native")
	rootACL := domainFixtureACL(config, "root")
	rootACL["createACLs"] = map[string]interface{}{"role": domainFixtureACL(config, "role")}
	record := func(id, kind, parent string, metadata map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"id": id, "name": id, "kind": kind, "parentId": parent, "metadata": metadata}
	}
	selected := record("associate", "fixture.associate", "product-root", map[string]interface{}{"fixture.acl": domainFixtureACL(config, "associate"), "fixture.accountId": "fixture-account", "fixture.label": "fixture", "fixture.roleIds": []string{}, "opaque": json.Number("9007199254740993")})
	spec := map[string]interface{}{"directory": directory, "name": "fixture", "forestId": "forest", "forestName": "fixture forest", "config": config, "records": []interface{}{record("account-root", "account", "forest", nil), record("product-root", "fixture.root", "account-root", map[string]interface{}{"fixture.acl": rootACL}), selected}}
	path := filepath.Join(parent, "owner.json")
	if err := os.WriteFile(path, domainFixtureJSON(t, spec), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/go", "test", "../internal", "-run", "^TestDomainFixtureProvisionOwner$", "-count=1", "-args", "-domain-fixture-owner-spec="+path)
	cmd.Env = domainFixtureGoEnvironment(t, parent)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("explicit fixture owner provisioning failed: %v\n%s", err, output)
	}
	return directory
}
func domainFixtureGoEnvironment(t *testing.T, parent string) []string {
	t.Helper()
	cache := filepath.Join(parent, "go-cache")
	if os.Getenv("GOPROXY") == "off" && os.Getenv("GOSUMDB") == "off" && os.Getenv("GOENV") == "off" {
		cache = os.Getenv("GOCACHE") // Reuse only the caller's explicitly scrubbed public build cache.
	}
	return []string{"PATH=/usr/bin:/bin", "HOME=" + parent, "GOROOT=/usr/lib/go", "GOPATH=" + filepath.Join(parent, "gopath"), "GOCACHE=" + cache, "GOMODCACHE=/home/persist/go/pkg/mod", "TMPDIR=" + parent, "GOENV=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off"}
}
func domainFixtureJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := engine.CanonicalDomainJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func domainFixtureVerifier(t *testing.T, config *DomainConfig) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var check engine.DomainCheck
		if r.Header.Get("Authorization") != "Bearer "+config.Trust.ChannelToken || json.NewDecoder(r.Body).Decode(&check) != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		actor := engine.DomainVerified{ContractRevision: engine.DomainRevision, PrincipalID: "fixture-human", Kind: "human", SessionID: "fixture-session", Scope: check.Intent.Scope, Intent: check.Intent, GrantRevision: "fixture-grant", AuthorityResourceRevision: "fixture-current", ExpiresAt: float64(time.Now().Unix()) + 30, Issuer: config.Trust.Issuer, Audience: check.Audience, Phase: check.Phase, LeaseBinding: check.LeaseBinding, ProofBinding: domainFixtureSHA(check.Proof)}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(domainFixtureJSON(t, actor))
	}))
	config.Trust.VerifierEndpoint = server.URL + "/internal/manifest-domain/check"
	t.Cleanup(server.Close)
	return server
}
