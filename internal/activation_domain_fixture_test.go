// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

type domainTestProduct struct{}

func (domainTestProduct) Resolve(input DomainInput, owned DomainOwnedScope, view DomainView) (DomainIntent, error) {
	var request struct {
		Scope     DomainScope `json:"scope"`
		Operation *string     `json:"operation"`
	}
	if err := json.Unmarshal(input.Body, &request); err != nil {
		return DomainIntent{}, err
	}
	resource := DomainResource{AccountID: owned.Binding.AccountID, Kind: "associate", ResourceID: "record-a"}
	root := DomainResource{AccountID: owned.Binding.AccountID, Kind: "root", ResourceID: owned.Binding.RootID}
	role := DomainResource{AccountID: owned.Binding.AccountID, Kind: "role", ResourceID: "role-a"}
	fields := []string{"roleIds"}
	if input.Mode == "read" {
		fields = []string{"id", "label", "roleIds"}
	}
	raw, err := domainTestCanonical(input.Body)
	if err != nil {
		return DomainIntent{}, err
	}
	return DomainIntent{ContractRevision: "manifest-associates/0.1", Scope: request.Scope, Binding: DomainBinding{request.Scope, owned.Binding.RootID, owned.Binding.BindingRevision}, Mode: input.Mode, Operation: request.Operation, Method: input.Method, Target: input.Target, RequestFingerprint: stagedHash(raw), Resources: []DomainResource{resource, role, root}, Fields: []DomainFieldSet{{resource, fields}, {role, []string{"reference"}}, {root, []string{"operation"}}}}, nil
}
func domainTestCanonical(raw []byte) ([]byte, error) {
	var value interface{}
	if err := DecodeDomainJSON(raw, &value); err != nil {
		return nil, err
	}
	return CanonicalDomainJSON(value)
}
func (domainTestProduct) Command(input DomainInput) (DomainCommand, error) {
	var command struct {
		CommandID        string `json:"commandId"`
		ExpectedRevision string `json:"expectedRevision"`
		Operation        string `json:"operation"`
	}
	err := json.Unmarshal(input.Body, &command)
	return DomainCommand{command.CommandID, command.ExpectedRevision, command.Operation}, err
}
func (domainTestProduct) Build(input DomainInput, owned DomainOwnedScope, view DomainView) (DomainDelta, error) {
	return DomainDelta{Writes: []DomainWrite{{NodeID: "record-a", Key: "roleIds", Value: []string{"role-a"}}}}, nil
}
func (domainTestProduct) Project(id string, intent DomainIntent, owned DomainOwnedScope, view DomainView) ([]byte, error) {
	return CanonicalDomainJSON(map[string]interface{}{"requestId": id, "revision": view.Revision, "label": view.Records["record-a"].Metadata["label"]})
}
func (domainTestProduct) PublicFields(kind string, fields []string, owned DomainOwnedScope) ([]string, error) {
	return fields, nil
}

type domainTestFixture struct {
	server       *Server
	config       DomainConfig
	wrongBinding bool
	mu           sync.Mutex
	seen         map[string]bool
}

func domainTestConfigured(t *testing.T) *domainTestFixture {
	t.Helper()
	f := &domainTestFixture{server: stagedTestServer(t, t.TempDir()), seen: map[string]bool{}}
	f.config = domainTestConfig()
	binding := f.config.Scopes[0].Binding
	root, _ := f.server.forest.GetNode("data-root")
	root.Kind = "test-root"
	root.Metadata = map[string]interface{}{"ownerAcl": domainTestACL()}
	record := stagedTestRecord(t, f.server.forest)
	record.Metadata["roleIds"] = []string{}
	record.Metadata["accountId"] = binding.AccountID
	record.Metadata["ownerAcl"] = domainTestACL()
	root.Children["role-a"] = &core.Node{ID: "role-a", Kind: "test-role", Name: "role", Parents: map[string]string{root.ID: root.Name}, Metadata: map[string]interface{}{"accountId": binding.AccountID, "ownerAcl": domainTestACL()}}
	callback := httptest.NewServer(http.HandlerFunc(f.callback))
	t.Cleanup(callback.Close)
	f.config.Trust.VerifierEndpoint = callback.URL + "/domain/verify"
	policy, err := NewDomainOwnerPolicy("ownerAcl")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.server.ConfigureDomain(f.config, map[string]DomainProduct{"manifest": domainTestProduct{}}, policy); err != nil {
		t.Fatal(err)
	}
	return f
}
func domainTestConfig() DomainConfig {
	binding := stagedTestBinding()
	binding.ProductID = "manifest"
	binding.BindingRevision = "owner-binding-1"
	return DomainConfig{Trust: ActivationConfig{ChannelToken: strings.Repeat("c", 32), Audience: "synthetic-native", Issuer: "synthetic-domain-owner", TimeoutMs: 1000, MaxProofBytes: 200, MaxBodyBytes: 20000, MaxResponseBytes: 20000, MaxLifetimeSeconds: 60, SyntheticLoopbackOnly: true}, HostID: "synthetic-host", ControlToken: strings.Repeat("h", 32), OwnerControlToken: strings.Repeat("o", 32), ACLMetadataKey: "ownerAcl", MaxLeases: 30, MaxRetainedEpochs: 100, MaxResources: 30, MaxFields: 20, MaxRequestBytes: 10000, MaxResponseBytes: 10000, Scopes: []DomainOwnedScope{{Binding: binding, Bounds: stagedTestBounds(), Layout: DomainLayout{Kinds: map[string]string{"root": "test-root", "associate": "synthetic-record", "role": "test-role"}}}}}
}
func domainTestACL() map[string]interface{} {
	grant := map[string]interface{}{"fields": []string{"id", "label", "roleIds", "reference", "operation"}, "reference": true}
	return map[string]interface{}{"contractRevision": "lj.domain.acl/1", "principals": map[string]interface{}{"external-human": map[string]interface{}{"read": grant, "associate.role.attach": grant}}}
}
func (f *domainTestFixture) callback(w http.ResponseWriter, r *http.Request) {
	var check DomainCheck
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(&check) != nil || r.Header.Get("Authorization") != "Bearer "+f.config.Trust.ChannelToken {
		w.WriteHeader(403)
		return
	}
	f.mu.Lock()
	seen := f.seen[check.Proof]
	f.seen[check.Proof] = true
	wrong := f.wrongBinding
	f.mu.Unlock()
	if seen {
		w.WriteHeader(403)
		return
	}
	proofBinding := stagedHash([]byte(check.Proof))
	if wrong {
		proofBinding = stagedHash([]byte("wrong-proof"))
	}
	actor := DomainVerified{ContractRevision: DomainRevision, PrincipalID: "external-human", Kind: "human", SessionID: "session-a", Scope: check.Intent.Scope, Intent: check.Intent, GrantRevision: "grant-1", AuthorityResourceRevision: "resources-1", ExpiresAt: domainNow() + 30, Issuer: f.config.Trust.Issuer, Audience: f.config.Trust.Audience, Phase: check.Phase, LeaseBinding: check.LeaseBinding, ProofBinding: proofBinding}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(actor)
}
func domainTestInput(t *testing.T, f *domainTestFixture, mode, id string) DomainRequest {
	t.Helper()
	body := map[string]interface{}{"contractRevision": "manifest-associates/0.1", "scope": DomainScope{"account-a", "manifest"}}
	if mode == "command" {
		view, err := f.server.readOwnedScope("owned-scope", stagedTestAllow)
		if err != nil {
			t.Fatal(err)
		}
		body["commandId"] = id
		body["expectedRevision"] = view.Revision
		body["operation"] = "associate.role.attach"
		body["payload"] = map[string]string{"associateId": "record-a", "roleId": "role-a"}
	}
	raw, err := CanonicalDomainJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	return DomainRequest{DomainInput: DomainInput{Mode: mode, Method: "POST", Target: "/synthetic/domain", Body: raw}, RequestID: "request-" + id, Proof: "admission-" + id}
}
func domainTestControl(f *domainTestFixture, begin DomainBegin, action string) DomainControl {
	return DomainControl{Action: action, Epoch: begin.Lease.Epoch, LeaseID: begin.Lease.LeaseID, HostID: f.config.HostID, ChannelToken: f.config.ControlToken}
}
func domainTestBegin(t *testing.T, f *domainTestFixture, request DomainRequest) DomainBegin {
	t.Helper()
	begin, err := f.server.DomainCall(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return begin
}
func domainTestReceive(t *testing.T, f *domainTestFixture, begin DomainBegin) DomainReceived {
	t.Helper()
	_, err := f.server.DomainControl(context.Background(), domainTestControl(f, begin, "adopt"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.server.DomainControl(context.Background(), domainTestControl(f, begin, "receive"))
	if err != nil {
		t.Fatal(err)
	}
	received, ok := result.Value.(DomainReceived)
	if !ok {
		t.Fatal(fmt.Errorf("wrong received type"))
	}
	return received
}
