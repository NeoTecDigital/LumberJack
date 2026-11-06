// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// Synthetic Core callback is an OWNED UNIT boundary, never live Auth acceptance.
type sourceUnitFixture struct {
	server  *Server
	p       *personalSource
	config  PersonalSourceConfig
	actor   SourceActor
	grant   SourcePersonalGrant
	mu      sync.Mutex
	revoked bool
	seen    map[string]bool
}

func sourceUnitConfig() PersonalSourceConfig {
	return PersonalSourceConfig{ContractRevision: PersonalSourceRevision, HostID: "unit-host", SourceAuthorityRef: "unit-native", SourcePolicyRevision: "unit-source-policy", ControlToken: strings.Repeat("u", 32), CoreCallback: SourceCoreCallback{Audience: "unit-audience", Issuer: "https://unit.invalid", Endpoint: "http://127.0.0.1:18086/verify", ChannelToken: strings.Repeat("v", 32)}, Bounds: PersonalSourceBounds{1 << 20, 1 << 20, 32, 32, 64, 64, 32, 32, 64, 30, 15}, StagedBounds: stagedTestBounds()}
}
func sourceUnitFixtureNew(t *testing.T) *sourceUnitFixture {
	t.Helper()
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	f := &sourceUnitFixture{server: stagedTestServer(t, t.TempDir()), config: sourceUnitConfig(), seen: map[string]bool{}}
	if err := os.Chmod(f.server.config.Process.DatabasePath, 0700); err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewServer(http.HandlerFunc(f.callback))
	t.Cleanup(callback.Close)
	f.config.CoreCallback.Endpoint = callback.URL + "/verify"
	if _, err := f.server.ConfigurePersonalSource(f.config); err != nil {
		t.Fatal(err)
	}
	f.p = f.server.personalSource.Load()
	evidence := SourceSubjectEvidence{f.config.CoreCallback.Issuer, "unit-subject", "authenticated", "unit-session", "aal2", "unit-request", domainNow(), domainNow() + 25}
	f.actor = SourceActor{"unit-principal", "human", evidence.SessionID, evidence}
	account := SourceAccount{AccountID: "unit-personal-account", AccountType: "personal", SubjectRef: core.PersonalSubjectRef{Kind: "user", SubjectID: "unit-canonical-user"}}
	f.grant = SourcePersonalGrant{f.actor.PrincipalID, SourceScope{account.AccountID, "momentum"}, account, []string{"identity.read", "unit.provision"}, "unit-base-1", "active"}
	return f
}
func (f *sourceUnitFixture) callback(w http.ResponseWriter, r *http.Request) {
	var check sourceProvisionCheck
	if json.NewDecoder(r.Body).Decode(&check) != nil || r.Header.Get("Authorization") != "Bearer "+f.config.CoreCallback.ChannelToken {
		w.WriteHeader(403)
		return
	}
	f.mu.Lock()
	denied := f.revoked || f.seen[check.Proof]
	f.seen[check.Proof] = true
	f.mu.Unlock()
	if denied {
		w.WriteHeader(403)
		return
	}
	f.p.mu.Lock()
	entry := f.p.candidates[check.Intent.CandidateRef]
	f.p.mu.Unlock()
	candidate, err := f.p.personalCandidate(entry, check.Phase)
	if err != nil {
		w.WriteHeader(403)
		return
	}
	actor := sourceProvisionVerified{PersonalProvisionRevision, f.actor.PrincipalID, "human", f.actor.SessionID, f.grant.Scope, f.grant.Account, "unit-sql-account-1", f.grant.Revision, candidate, f.actor.Evidence.RequestID, sourceCommandKey(check.Intent), "unit-core-policy", check.Intent, check.Phase, check.Lease, min(candidate.ValidUntil, domainNow()+20), check.Audience, f.config.CoreCallback.Issuer, stagedHash([]byte(check.Proof))}
	_ = json.NewEncoder(w).Encode(actor)
}
func sourceUnitRequest(f *sourceUnitFixture, action string, payload interface{}) SourceEnvelope {
	raw, _ := CanonicalDomainJSON(payload)
	return SourceEnvelope{PersonalSourceRevision, action, f.p.epoch, f.config.HostID, f.config.ControlToken, f.actor.Evidence.RequestID, domainNow() + 10, raw}
}
func sourceUnitPrepared(t *testing.T, f *sourceUnitFixture) (*personalProvisionEntry, json.RawMessage) {
	t.Helper()
	input := sourceProvisionPrepare{"unit-command", f.actor.PrincipalID, f.grant.Account, SourceEnrollment{CommandID: "unit-enroll", Revision: "unit-enroll-1", Enrollment: core.PersonalEnrollmentSpec{Mode: "new"}}, nil, "prepare", f.actor, f.grant, f.server.forest.ID, f.config.SourcePolicyRevision}
	got, err := f.p.preparePersonal(sourceUnitRequest(f, "provision.resolve", input))
	if err != nil {
		t.Fatal(err)
	}
	c := got.(SourceProspectiveCandidate)
	payload := PersonalProvisionPayload{c.CommandID, c.PrincipalID, f.grant.Scope, f.grant.Account, input.EnrollmentReference, c.RuntimeID, c.RootID, c.OwnerID, nil, c.PolicyRevision, c.CandidateRef}
	raw, _ := CanonicalDomainJSON(payload)
	intent, err := personalIntentFromCommand(raw, f.config)
	if err != nil {
		t.Fatal(err)
	}
	guard := sourceProvisionGuard{"guard", f.actor, f.grant, intent, "admission", nil, nil}
	result, err := f.p.guardPersonal(context.Background(), sourceUnitRequest(f, "provision.resolve", guard))
	if err != nil {
		t.Fatal(err)
	}
	lease := result.(sourceProvisionGuardResult).LeaseRef
	if _, err = f.p.leaseRelease(context.Background(), sourceUnitRequest(f, "lease.release", sourceLeaseRelease{lease, "released"})); err != nil {
		t.Fatal(err)
	}
	return f.p.candidates[c.CandidateRef], raw
}
func sourceUnitAdmitted(t *testing.T, f *sourceUnitFixture) (*personalProvisionEntry, json.RawMessage, sourcePersonalAdmissionResult) {
	t.Helper()
	entry, raw := sourceUnitPrepared(t, f)
	got, err := f.p.admitPersonal(context.Background(), sourceUnitRequest(f, "provision.admit", sourcePersonalAdmit{raw, "unit_admission_proof"}))
	if err != nil {
		t.Fatal(err)
	}
	return entry, raw, got.(sourcePersonalAdmissionResult)
}
func sourceUnitCommitted(t *testing.T, f *sourceUnitFixture) (*personalProvisionEntry, json.RawMessage, sourcePersonalAdmissionResult) {
	t.Helper()
	entry, raw, admission := sourceUnitAdmitted(t, f)
	if _, err := f.p.executePersonal(context.Background(), sourceUnitRequest(f, "binding.provision", sourcePersonalExecute{raw, admission.ExecutionLease, "unit_execution_proof"})); err != nil {
		t.Fatal(err)
	}
	return entry, raw, admission
}
func TestPersonalSourceClosedConfigurationAndRawBody(t *testing.T) {
	cfg := sourceUnitConfig()
	cfg.StagedBounds = stagedBounds{}
	if validatePersonalSourceConfig(cfg) == nil {
		t.Fatal("missing staged bounds defaulted")
	}
	f := sourceUnitFixtureNew(t)
	entry, raw := sourceUnitPrepared(t, f)
	var body PersonalProvisionPayload
	if sourceDecode(raw, &body, f.config.Bounds) != nil {
		t.Fatal("own closed command refused")
	}
	altered := append([]byte(" \n"), raw...)
	intent, err := personalIntentFromCommand(altered, f.config)
	if err != nil || intent.CommandSHA256 != entry.intent.CommandSHA256 || intent.RequestSHA256 == entry.intent.RequestSHA256 {
		t.Fatal("original bytes/stable SHA collapsed")
	}
	raw = append(raw[:len(raw)-1], []byte(`,"other":true}`)...)
	if sourceDecode(raw, &body, f.config.Bounds) == nil {
		t.Fatal("unknown command accepted")
	}
}
