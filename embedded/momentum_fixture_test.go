// Written by Richard Christopher, Copyright 2026 Mindfull
package embedded

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/momentum"
)

func momentumFixtureConfig() DomainConfig {
	config := domainFixtureConfig()
	owned := &config.Scopes[0]
	owned.Binding.ProductID = "momentum"
	owned.Bounds.MaxChanges, owned.Bounds.MaxReceipts = 100, 100
	fields := append([]string{"id", "children", "permission"}, momentum.Fields...)
	layout := engine.DomainLayout{ContractRevision: momentum.Revision,
		Kinds:  map[string]string{"root": "activity.momentum.root", "work": "activity.momentum.work"},
		Fields: map[string]string{}, Routes: map[string]engine.DomainRoute{}, Profiles: map[string]map[string][]string{}}
	for _, field := range momentum.Fields {
		layout.Fields[field] = "activity.momentum." + field
	}
	for _, operation := range momentum.Operations {
		method, target := "POST", "/api/workspace/commands"
		if operation == "read" {
			method, target = "GET", "/api/workspace"
		}
		layout.Routes[operation] = engine.DomainRoute{Method: method, Target: target}
		layout.Profiles[operation] = map[string][]string{"root": fields, "work": fields}
	}
	owned.Layout = layout
	return config
}

func momentumFixtureACL(config DomainConfig, root bool) map[string]interface{} {
	fields := config.Scopes[0].Layout.Profiles["read"]["root"]
	grants := map[string]interface{}{}
	for _, operation := range momentum.Operations {
		grants[operation] = map[string]interface{}{"fields": fields, "reference": true, "createKinds": []string{"work"}}
	}
	acl := map[string]interface{}{"contractRevision": "lj.domain.acl/1", "principals": map[string]interface{}{"fixture-human": grants}}
	if root {
		acl["createACLs"] = map[string]interface{}{"work": momentumFixtureACL(config, false)}
	}
	return acl
}

func provisionMomentumFixture(t *testing.T, config DomainConfig) string {
	t.Helper()
	parent := t.TempDir()
	directory := filepath.Join(parent, "native")
	record := func(id, kind, parent string, metadata map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"id": id, "name": id, "kind": kind, "parentId": parent, "metadata": metadata}
	}
	root := record("product-root", "activity.momentum.root", "account-root", map[string]interface{}{
		config.ACLMetadataKey: momentumFixtureACL(config, true), "fixture.hidden": "never-disclose"})
	spec := map[string]interface{}{"directory": directory, "name": "fixture", "forestId": "forest", "forestName": "fixture forest", "config": config,
		"records": []interface{}{record("account-root", "account", "forest", nil), root}}
	path := filepath.Join(parent, "owner.json")
	if err := os.WriteFile(path, domainFixtureJSON(t, spec), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/go", "test", "../internal", "-run", "^TestDomainFixtureProvisionOwner$", "-count=1", "-args", "-domain-fixture-owner-spec="+path)
	cmd.Env = domainFixtureGoEnvironment(t, parent)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("explicit disposable Momentum owner provisioning failed: %v\n%s", err, output)
	}
	return directory
}

func momentumFixtureVerifier(t *testing.T, config *DomainConfig) *atomic.Bool {
	t.Helper()
	revoked := &atomic.Bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var check engine.DomainCheck
		if revoked.Load() || r.Header.Get("Authorization") != "Bearer "+config.Trust.ChannelToken || json.NewDecoder(r.Body).Decode(&check) != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		principal := "fixture-human"
		if check.Proof == "fixture-other-human" {
			principal = "fixture-other-human"
		}
		actor := engine.DomainVerified{ContractRevision: engine.DomainRevision, PrincipalID: principal, Kind: "human", SessionID: "fixture-session",
			Scope: check.Intent.Scope, Intent: check.Intent, GrantRevision: "fixture-grant", AuthorityResourceRevision: "fixture-current",
			ExpiresAt: float64(time.Now().Unix()) + 30, Issuer: config.Trust.Issuer, Audience: check.Audience,
			Phase: check.Phase, LeaseBinding: check.LeaseBinding, ProofBinding: domainFixtureSHA(check.Proof)}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(domainFixtureJSON(t, actor))
	}))
	config.Trust.VerifierEndpoint = server.URL + "/internal/labelled-momentum-proof"
	t.Cleanup(server.Close)
	return revoked
}

func openMomentumFixture(t *testing.T, config DomainConfig, directory string) *Handle {
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

func momentumInput(t *testing.T, operation, id, revision string, payload map[string]interface{}) DomainRequest {
	t.Helper()
	body := map[string]interface{}{"contractRevision": momentum.Revision, "scope": engine.DomainScope{AccountID: "fixture-account", Product: "momentum"}}
	mode, method, target := "read", "GET", "/api/workspace"
	if operation != "read" {
		mode, method, target = "command", "POST", "/api/workspace/commands"
		body["operation"], body["commandId"], body["expectedRevision"], body["payload"] = operation, id, revision, payload
	}
	return DomainRequest{DomainInput: DomainInput{Mode: mode, Method: method, Target: target, Body: domainFixtureJSON(t, body)}, RequestID: "fixture-request", Proof: "fixture-admission"}
}

func momentumResult(t *testing.T, handle *Handle, config DomainConfig, input DomainRequest) map[string]interface{} {
	t.Helper()
	begin, received := domainFixtureExchange(t, handle, config, input)
	var body map[string]interface{}
	if err := json.Unmarshal(received.Body, &body); err != nil {
		t.Fatal(err)
	}
	_ = domainFixtureControlCall(t, domainFixtureFinish(t, config, begin))
	return body
}
