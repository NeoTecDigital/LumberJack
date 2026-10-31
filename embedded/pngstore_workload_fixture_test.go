// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"encoding/json"
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"os"
	"testing"
	"time"
)

const (
	pngWorkloadArtifact  = "testdata/workload_profile.json"
	pngWorkloadPrincipal = "workload:alive5-sync"
	pngWorkloadSession   = "workload-session:alive5-sync:run-1"
	pngWorkloadIssuer    = "workload-authority:labelled"
	pngWorkloadRevision  = "labelled-workload-grant-1"
	pngWorkloadContacts  = "resource:png_source.messaging.contacts"
	pngWorkloadThreads   = "resource:png.conversations"
)

// What a proof answers. The test changes one thing at a time to show the engine refuses it.
type pngWorkloadProof struct {
	kind, principal, session, issuer, revision string
}

func pngWorkloadValidProof() pngWorkloadProof {
	return pngWorkloadProof{"workload", pngWorkloadPrincipal, pngWorkloadSession, pngWorkloadIssuer, pngWorkloadRevision}
}

type pngWorkloadRun struct {
	*pngACLRun
	families map[string][]string
}

func pngWorkloadFamilies(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(pngWorkloadArtifact)
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		Families map[string][]string `json:"workloadFamilies"`
	}
	if err = json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	return artifact.Families
}

func pngWorkloadStart(t *testing.T, directory string) *pngWorkloadRun {
	t.Helper()
	families := pngWorkloadFamilies(t)
	previous := pngACLConfigure
	pngACLConfigure = func(config *DomainConfig) {
		config.WorkloadPolicy = &engine.DomainWorkloadPolicy{Issuer: pngWorkloadIssuer, Families: families}
	}
	t.Cleanup(func() { pngACLConfigure = previous })
	run := pngACLStart(t, pngWorkloadArtifact, directory)
	run.authority.targetRevision = pngWorkloadRevision
	return &pngWorkloadRun{pngACLRun: run, families: families}
}

func (run *pngWorkloadRun) issue(proof pngWorkloadProof, intent engine.DomainIntent, phase string, lease *engine.DomainLease) string {
	authority := run.authority.domain
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.sequence++
	token := fmt.Sprintf("png_workload_ticket_%d", authority.sequence)
	authority.tickets[token] = engine.DomainVerified{ContractRevision: engine.DomainRevision, PrincipalID: proof.principal, Kind: proof.kind, SessionID: proof.session, Scope: intent.Scope, Intent: intent, GrantRevision: proof.revision, AuthorityResourceRevision: "labelled-current", ExpiresAt: float64(time.Now().Unix()) + 30, Issuer: proof.issuer, Audience: authority.config.Trust.Audience, Phase: phase, LeaseBinding: lease, ProofBinding: domainFixtureSHA(token)}
	return token
}

// The whole exchange as a workload makes it. A refusal at any stage is returned, not fatal.
func (run *pngWorkloadRun) as(proof pngWorkloadProof, request pngstore.Request, mode string) (map[string]interface{}, error) {
	run.t.Helper()
	input := pngFixtureInput(run.t, request, mode)
	raw, err := run.handle.DomainResolve(domainFixtureJSON(run.t, input))
	if err != nil {
		return nil, err
	}
	var intent engine.DomainIntent
	if err = engine.DecodeDomainJSON(raw, &intent); err != nil {
		return nil, err
	}
	raw, err = run.handle.DomainCall(domainFixtureJSON(run.t, DomainRequest{DomainInput: input, RequestID: "labelled-workload-request", Proof: run.issue(proof, intent, "admission", nil)}))
	if err != nil {
		return nil, err
	}
	var begin engine.DomainBegin
	if err = engine.DecodeDomainJSON(raw, &begin); err != nil {
		return nil, err
	}
	return run.settleWorkload(proof, begin, intent, mode)
}

func (run *pngWorkloadRun) settleWorkload(proof pngWorkloadProof, begin engine.DomainBegin, intent engine.DomainIntent, mode string) (map[string]interface{}, error) {
	run.t.Helper()
	_ = domainFixtureControlCall(run.t, domainFixtureControl(run.config, begin, "adopt"))
	var received engine.DomainReceived
	if err := engine.DecodeDomainJSON(domainFixtureControlCall(run.t, domainFixtureControl(run.config, begin, "receive")), &received); err != nil {
		return nil, err
	}
	var body map[string]interface{}
	if err := engine.DecodeDomainJSON(received.Body, &body); err != nil {
		return nil, err
	}
	handoff := domainFixtureControl(run.config, begin, "handoff")
	handoff.Proof = run.issue(proof, intent, "handoff", &begin.Lease)
	raw, err := DomainControlCall(domainFixtureJSON(run.t, handoff))
	if err != nil {
		return nil, err
	}
	var permit engine.DomainPermit
	if err = engine.DecodeDomainJSON(raw, &permit); err != nil {
		return nil, err
	}
	finish := domainFixtureControl(run.config, begin, "finish")
	finish.ResponseHash, finish.Disposition, finish.PermitID = begin.ResponseHash, "handed-off", permit.PermitID
	_ = domainFixtureControlCall(run.t, finish)
	if mode == "command" && received.Pair != nil {
		run.revision = received.Pair.Revision
	}
	return body, nil
}

func (run *pngWorkloadRun) query(family string, fields ...string) pngstore.Request {
	return pngstore.Request{ContractRevision: pngstore.Revision, Scope: run.scope, Action: "labelled.sync", Query: pngstore.Query{Family: family, Limit: 50, Fields: fields}}
}

func (run *pngWorkloadRun) command(mutations ...pngstore.Mutation) pngstore.Request {
	run.sequence++
	return pngstore.Request{ContractRevision: pngstore.Revision, Scope: run.scope, Action: "labelled.sync", Operation: pngstore.WriteOperation, CommandID: fmt.Sprintf("labelled-sync-%d", run.sequence), ExpectedRevision: run.revision, Mutations: mutations}
}

func (run *pngWorkloadRun) newRow(family string, fields map[string]interface{}) pngstore.Mutation {
	run.sequence++
	key := fmt.Sprintf("labelled-row-%07d", run.sequence)
	data := map[string]interface{}{"id": key, "account_id": run.scope.AccountID}
	for name, value := range fields {
		data[name] = value
	}
	return pngstore.Mutation{Family: family, Key: key, Data: data}
}

// A person's write, to put rows the workload must not be able to touch in front of it.
func (run *pngWorkloadRun) asAdministrator(mutations ...pngstore.Mutation) []pngstore.Record {
	run.t.Helper()
	body, err := run.call(run.command(mutations...), "command", pngACLAdministrator)
	if err != nil {
		run.t.Fatal("administrator write refused", err)
	}
	return pngWorkloadRecords(run.t, body)
}

func pngWorkloadRecords(t *testing.T, body map[string]interface{}) []pngstore.Record {
	t.Helper()
	var result struct {
		Records []pngstore.Record `json:"records"`
	}
	if err := engine.DecodeDomainJSON(domainFixtureJSON(t, body["data"]), &struct {
		Records *[]pngstore.Record `json:"records"`
		Result  interface{}        `json:"result"`
	}{Records: &result.Records}); err != nil {
		t.Fatal(err)
	}
	return result.Records
}

func pngWorkloadPatch(record pngstore.Record, fields map[string]interface{}) pngstore.Mutation {
	return pngstore.Mutation{Family: record.Family, Key: record.Key, NativeID: record.NativeID, ExpectedVersion: record.Version, Data: fields, Patch: true}
}
