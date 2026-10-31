// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"bytes"
	"encoding/json"
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// Labelled records on the real business profile with the real two-principal shape: a named owner
// and an acting administrator. Nothing here reads an installation or customer data.
const (
	pngACLOwner         = "labelled-owner"
	pngACLAdministrator = "fixture-human"
	pngACLMember        = "labelled-member"
)

type pngACLArtifact struct {
	Family string                     `json:"family"`
	Fields []string                   `json:"columns"`
	Grants map[string]json.RawMessage `json:"administrationGrants"`
}

type pngACLAuthority struct {
	pngEnrolledAuthority
	targetRevision string
}

type pngACLRun struct {
	t         *testing.T
	handle    *Handle
	config    DomainConfig
	authority *pngACLAuthority
	artifact  pngACLArtifact
	scope     engine.DomainScope
	directory string
	revision  string
	sequence  int
}

func pngACLVerifier(t *testing.T, config *DomainConfig) *pngACLAuthority {
	domain := &pngFixtureAuthority{config: config, tickets: map[string]engine.DomainVerified{}, current: true}
	authority := &pngACLAuthority{pngEnrolledAuthority: pngEnrolledAuthority{domain: domain, consumed: map[string]bool{}}, targetRevision: "labelled-grant-1"}
	server := httptest.NewServer(http.HandlerFunc(authority.answer))
	config.Trust.VerifierEndpoint = server.URL + "/internal/manifest-domain/check"
	t.Cleanup(server.Close)
	return authority
}

func (authority *pngACLAuthority) answer(w http.ResponseWriter, request *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(request.Body, 1000001))
	var shape map[string]json.RawMessage
	if err != nil || len(raw) > 1000000 || engine.DecodeDomainJSON(raw, &shape) != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if shape["request"] == nil {
		request.Body = io.NopCloser(bytes.NewReader(raw))
		authority.domain.check(w, request)
		return
	}
	var check engine.EnrollmentCheck
	if engine.DecodeDomainJSON(raw, &check) != nil || request.Header.Get("Authorization") != "Bearer "+authority.domain.config.Trust.ChannelToken {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(authority.actor(check))
}

func (authority *pngACLAuthority) actor(check engine.EnrollmentCheck) engine.EnrollmentVerified {
	authority.expires = float64(time.Now().Unix()) + 30
	actor := authority.enrollmentActor(check)
	actor.ContractRevision = check.ContractRevision
	if check.Request.Administration != nil {
		actor.OwnerAuthorized, actor.AdministratorAuthorized = false, true
		return actor
	}
	actor.PrincipalID = pngACLOwner
	if actor.PrincipalReference != nil {
		actor.PrincipalReference.ActorPrincipalID = pngACLOwner
		actor.PrincipalReference.TargetGrantRevision = &authority.targetRevision
	}
	return actor
}

func pngACLReadArtifact(t *testing.T, path string) pngACLArtifact {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var artifact pngACLArtifact
	if err = json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	return artifact
}

func pngACLConfig(t *testing.T, path string) DomainConfig {
	t.Helper()
	config := pngProtectedConfig(t, path)
	config.MaxResources, config.MaxFields, config.MaxLeases = 1024, 1024, 4096
	return config
}

func pngACLAdministration(t *testing.T, artifact pngACLArtifact) *engine.EnrollmentAdministration {
	t.Helper()
	body := map[string]interface{}{"ownerPrincipalId": pngACLOwner, "name": "LABELLED organization", "authorizationId": "66cbb392-26df-45ec-bbfe-5d8592609391", "authorizationDigest": domainFixtureSHA("labelled approved spec"), "grants": artifact.Grants}
	var administration engine.EnrollmentAdministration
	if err := engine.DecodeDomainJSON(domainFixtureJSON(t, body), &administration); err != nil {
		t.Fatal(err)
	}
	return &administration
}

func pngACLStart(t *testing.T, artifactPath, directory string) *pngACLRun {
	t.Helper()
	config := pngACLConfig(t, artifactPath)
	run := &pngACLRun{t: t, config: config, artifact: pngACLReadArtifact(t, artifactPath), directory: directory, scope: engine.DomainScope{AccountID: "labelled-account", Product: "manifest"}}
	run.authority = pngACLVerifier(t, &run.config)
	run.handle = openPNGFixture(t, directory, run.config)
	return run
}

func (run *pngACLRun) provision() {
	run.t.Helper()
	input := engine.EnrollmentInput{ContractRevision: engine.EnrollmentAdminProofRevision, RequestID: "labelled-provision", Proof: "labelled_provision", Request: engine.EnrollmentRequest{ContractRevision: engine.EnrollmentAdminRevision, Scope: run.scope, CommandID: "labelled-provision", ExpectedRevision: "absent", Operation: engine.EnrollmentProvision, ProfileRef: run.config.ProvisioningProfile.ProfileRef, Administration: pngACLAdministration(run.t, run.artifact)}}
	run.enroll(input)
	run.refreshRevision()
}

func (run *pngACLRun) enroll(input engine.EnrollmentInput) {
	run.t.Helper()
	run.authority.domain.mu.Lock()
	run.authority.input, run.authority.lease = input, nil
	run.authority.domain.mu.Unlock()
	begin := pngActualEnrollment(run.t, run.handle, run.config, input, &run.authority.pngEnrolledAuthority)
	if begin.Lease.LeaseID == "" {
		run.t.Fatal("labelled enrollment lease absent")
	}
}

func (run *pngACLRun) refreshRevision() {
	run.t.Helper()
	run.revision = pngActualGraphRead(run.t, run.handle, run.config, run.authority.domain, run.scope)["revision"].(string)
}

func (run *pngACLRun) readGrantChange(operation, target, revision string) error {
	run.t.Helper()
	run.refreshRevision()
	run.sequence++
	run.authority.targetRevision = revision
	id := fmt.Sprintf("labelled-%s-%d", operation, run.sequence)
	input := engine.EnrollmentInput{ContractRevision: engine.EnrollmentProofRevision, RequestID: id, Proof: "labelled_" + domainFixtureSHA(id), Request: engine.EnrollmentRequest{ContractRevision: engine.EnrollmentRevision, Scope: run.scope, CommandID: id, ExpectedRevision: run.revision, Operation: operation, TargetPrincipalID: &target, ProfileRef: run.config.ProvisioningProfile.ProfileRef}}
	run.authority.domain.mu.Lock()
	run.authority.input, run.authority.lease = input, nil
	run.authority.domain.mu.Unlock()
	raw, err := run.handle.DomainEnrollJSON(domainFixtureJSON(run.t, input))
	if err != nil {
		return err
	}
	var begin engine.DomainBegin
	if err = engine.DecodeDomainJSON(raw, &begin); err != nil {
		return err
	}
	run.settleEnrollment(input, begin)
	run.refreshRevision()
	return nil
}

func (run *pngACLRun) settleEnrollment(input engine.EnrollmentInput, begin engine.DomainBegin) {
	run.t.Helper()
	run.authority.domain.mu.Lock()
	run.authority.lease = &begin.Lease
	run.authority.domain.mu.Unlock()
	_ = domainFixtureControlCall(run.t, domainFixtureControl(run.config, begin, "adopt"))
	_ = domainFixtureControlCall(run.t, domainFixtureControl(run.config, begin, "receive"))
	handoff := domainFixtureControl(run.config, begin, "handoff")
	handoff.Proof = input.Proof + "_handoff"
	var permit engine.DomainPermit
	if err := engine.DecodeDomainJSON(domainFixtureControlCall(run.t, handoff), &permit); err != nil {
		run.t.Fatal(err)
	}
	finish := domainFixtureControl(run.config, begin, "finish")
	finish.ResponseHash, finish.Disposition, finish.PermitID = begin.ResponseHash, "handed-off", permit.PermitID
	_ = domainFixtureControlCall(run.t, finish)
}

func (run *pngACLRun) row(key string) map[string]interface{} {
	data := map[string]interface{}{"id": key, "account_id": run.scope.AccountID}
	for _, column := range run.artifact.Fields[:20] {
		data[column] = "LABELLED generated value " + key
	}
	return data
}

func (run *pngACLRun) writeRows(count int) error {
	run.t.Helper()
	return run.writeRowsAs(count, pngACLAdministrator)
}

func (run *pngACLRun) writeRowsAs(count int, principal string) error {
	run.t.Helper()
	mutations := make([]pngstore.Mutation, 0, count)
	for index := 0; index < count; index++ {
		run.sequence++
		key := fmt.Sprintf("labelled-%07d", run.sequence)
		mutations = append(mutations, pngstore.Mutation{Family: run.artifact.Family, Key: key, Data: run.row(key)})
	}
	_, err := run.call(run.writeRequest(mutations), "command", principal)
	return err
}

func (run *pngACLRun) writeRequest(mutations []pngstore.Mutation) pngstore.Request {
	run.sequence++
	return pngstore.Request{ContractRevision: pngstore.Revision, Scope: run.scope, Action: "labelled.write", Operation: pngstore.WriteOperation, CommandID: fmt.Sprintf("labelled-write-%d", run.sequence), ExpectedRevision: run.revision, Mutations: mutations}
}

func (run *pngACLRun) readRequest(query pngstore.Query) pngstore.Request {
	query.Family = run.artifact.Family
	return pngstore.Request{ContractRevision: pngstore.Revision, Scope: run.scope, Action: "labelled.read", Query: query}
}

// The body is only returned after the full exchange: resolve, proof, begin, receive and finish.
func (run *pngACLRun) call(request pngstore.Request, mode, principal string) (map[string]interface{}, error) {
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
	proof := run.authority.domain.issue(intent, "admission", nil, principal)
	raw, err = run.handle.DomainCall(domainFixtureJSON(run.t, DomainRequest{DomainInput: input, RequestID: "labelled-request", Proof: proof}))
	if err != nil {
		return nil, err
	}
	var begin engine.DomainBegin
	if err = engine.DecodeDomainJSON(raw, &begin); err != nil {
		return nil, err
	}
	return run.settle(begin, intent, mode)
}

func (run *pngACLRun) settle(begin engine.DomainBegin, intent engine.DomainIntent, mode string) (map[string]interface{}, error) {
	run.t.Helper()
	_ = domainFixtureControlCall(run.t, domainFixtureControl(run.config, begin, "adopt"))
	var received engine.DomainReceived
	if err := engine.DecodeDomainJSON(domainFixtureControlCall(run.t, domainFixtureControl(run.config, begin, "receive")), &received); err != nil {
		return nil, err
	}
	if mode == "command" {
		if received.Pair == nil {
			return nil, fmt.Errorf("labelled command had no durable pair")
		}
		run.revision = received.Pair.Revision
	}
	var body map[string]interface{}
	if err := engine.DecodeDomainJSON(received.Body, &body); err != nil {
		return nil, err
	}
	pngFixtureFinish(run.t, run.config, run.authority.domain, pngFixtureExchange{begin: begin, received: received, intent: intent}, true)
	return body, nil
}

func (run *pngACLRun) readPage(limit int, principal string) error {
	run.t.Helper()
	_, err := run.call(run.readRequest(pngstore.Query{Limit: limit, Fields: []string{"id", "account_id", run.artifact.Fields[0]}}), "read", principal)
	return err
}
