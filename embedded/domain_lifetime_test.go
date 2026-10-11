// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	engine "github.com/NeoTecDigital/LumberJack/internal"
)

func domainFixtureSHA(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}
func TestDomainRealManifestPairPinsAndLateFinishAfterClose(t *testing.T) {
	config := domainFixtureConfig()
	_ = domainFixtureVerifier(t, &config)
	directory := provisionDomainFixture(t, config)
	handle, err := OpenPath("fixture", directory, "fixture", "fixture-private-owner")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if _, err = handle.ConfigureDomain(domainFixtureJSON(t, config)); err != nil {
		t.Fatal(err)
	}
	revision := domainFixtureRead(t, handle, config)
	begin, received, intent := domainFixtureRole(t, handle, config, revision)
	if received.Pair == nil || received.Pair.Sequence == 0 || !strings.Contains(string(received.Body), `"status":"applied"`) {
		t.Fatal("real compiled product command lacks paired actual publisher witness")
	}
	rt := handle.runtime
	if err = handle.Close(); err != nil {
		t.Fatal(err)
	}
	registryMu.Lock()
	pinned := rt.refs > 0 && registry[rt.path] == rt
	registryMu.Unlock()
	if !pinned {
		t.Fatal("handle close released delegated lease runtime/flock")
	}
	validate := domainFixtureControl(config, begin, "validate")
	validate.LeaseBinding, validate.Intent = &begin.Lease, &intent
	validate.PrincipalID, validate.SessionID, validate.ValidUntil = begin.Lease.PrincipalID, begin.Lease.SessionID, 1e12
	_ = domainFixtureControlCall(t, validate)
	finish := domainFixtureFinish(t, config, begin)
	_ = domainFixtureControlCall(t, finish)
	_ = domainFixtureControlCall(t, finish) // Actual authenticated late ACK retry after shutdown.
	registryMu.Lock()
	closed := rt.refs == 0 && registry[rt.path] == nil
	registryMu.Unlock()
	if !closed {
		t.Fatal("completed paired obligation did not release real runtime/flock")
	}
	owner, _ := lookupDomainOwner(begin.Lease.Epoch)
	registryMu.Lock()
	heavy := owner.runtime != nil
	registryMu.Unlock()
	if heavy {
		t.Fatal("completion archive retained heavy native runtime")
	}
}
func domainFixtureControl(config DomainConfig, begin engine.DomainBegin, action string) DomainControl {
	return DomainControl{Action: action, Epoch: begin.Lease.Epoch, LeaseID: begin.Lease.LeaseID, HostID: config.HostID, ChannelToken: config.ControlToken}
}
func domainFixtureControlCall(t *testing.T, input DomainControl) []byte {
	t.Helper()
	output, err := DomainControlCall(domainFixtureJSON(t, input))
	if err != nil {
		t.Fatal(err)
	}
	return output
}
func domainFixtureFinish(t *testing.T, config DomainConfig, begin engine.DomainBegin) DomainControl {
	t.Helper()
	handoff := domainFixtureControl(config, begin, "handoff")
	handoff.Proof = "fixture-fresh-handoff"
	var permit engine.DomainPermit
	if err := engine.DecodeDomainJSON(domainFixtureControlCall(t, handoff), &permit); err != nil {
		t.Fatal(err)
	}
	finish := domainFixtureControl(config, begin, "finish")
	finish.ResponseHash, finish.Disposition, finish.PermitID = begin.ResponseHash, "handed-off", permit.PermitID
	return finish
}
func domainFixtureRead(t *testing.T, handle *Handle, config DomainConfig) string {
	t.Helper()
	body := map[string]interface{}{"contractRevision": "manifest-associates/0.1", "scope": engine.DomainScope{AccountID: "fixture-account", Product: "manifest"}}
	input := DomainRequest{DomainInput: DomainInput{Mode: "read", Method: "POST", Target: "/fixture/read", Body: domainFixtureJSON(t, body)}, RequestID: "fixture-read", Proof: "fixture-admission"}
	begin, received := domainFixtureExchange(t, handle, config, input)
	if strings.Contains(string(received.Body), "opaque") || strings.Contains(string(received.Body), "fixture.acl") {
		t.Fatal("projection leaked source preservation/ACL bags")
	}
	var result struct {
		Graph struct {
			Revision string `json:"revision"`
		} `json:"graph"`
	}
	if err := json.Unmarshal(received.Body, &result); err != nil {
		t.Fatal(err)
	}
	finish := domainFixtureControl(config, begin, "finish")
	finish.ResponseHash, finish.Disposition = begin.ResponseHash, "irrevocably-discarded"
	_ = domainFixtureControlCall(t, finish)
	return result.Graph.Revision
}
func domainFixtureRole(t *testing.T, handle *Handle, config DomainConfig, revision string) (engine.DomainBegin, engine.DomainReceived, engine.DomainIntent) {
	t.Helper()
	body := map[string]interface{}{"contractRevision": "manifest-associates/0.1", "scope": engine.DomainScope{AccountID: "fixture-account", Product: "manifest"}, "commandId": "fixture-define-role", "expectedRevision": revision, "operation": "role.define", "payload": map[string]interface{}{"label": "<>&\u2028\u2029🙂"}}
	input := DomainRequest{DomainInput: DomainInput{Mode: "command", Method: "POST", Target: "/fixture/role.define", Body: domainFixtureJSON(t, body)}, RequestID: "fixture-command", Proof: "fixture-admission"}
	raw, err := handle.DomainResolve(domainFixtureJSON(t, input.DomainInput))
	var intent engine.DomainIntent
	if err != nil || engine.DecodeDomainJSON(raw, &intent) != nil {
		t.Fatal("native intent resolve failed", err)
	}
	begin, received := domainFixtureExchange(t, handle, config, input)
	return begin, received, intent
}
func domainFixtureExchange(t *testing.T, handle *Handle, config DomainConfig, input DomainRequest) (engine.DomainBegin, engine.DomainReceived) {
	t.Helper()
	raw, err := handle.DomainCall(domainFixtureJSON(t, input))
	var begin engine.DomainBegin
	if err != nil || engine.DecodeDomainJSON(raw, &begin) != nil {
		t.Fatal("native begin failed", err)
	}
	_ = domainFixtureControlCall(t, domainFixtureControl(config, begin, "adopt"))
	var received engine.DomainReceived
	if err = engine.DecodeDomainJSON(domainFixtureControlCall(t, domainFixtureControl(config, begin, "receive")), &received); err != nil {
		t.Fatal(err)
	}
	return begin, received
}
