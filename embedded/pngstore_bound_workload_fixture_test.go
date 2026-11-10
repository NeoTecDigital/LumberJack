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
	"sort"
	"strings"
	"testing"
	"time"
)

const pngBoundPolicyRevision = "manifest-native-workload-policy/0.2"
const pngBoundGrantRevision = "manifest-workload-grant/0.2"
const pngBoundRunRevision = "manifest-workload-run/0.1"
const pngBoundHandoffRevision = "manifest-workload-handoff/0.1"

type pngBoundAuthority struct {
	*pngACLAuthority
	grants map[string]engine.DomainWorkloadGrant
	runs   map[string]engine.DomainWorkloadRun
}

type pngBoundRun struct {
	*pngWorkloadRun
	bound *pngBoundAuthority
}

// This explicitly synthetic profile is widened before its FIRST enrollment.
// Installed production profiles, identities and owner defaults are never altered.
func pngBoundConfig(t *testing.T) DomainConfig {
	t.Helper()
	config := pngACLConfig(t, pngWorkloadArtifact)
	config.WorkloadPolicy = pngBoundPolicy(t)
	for _, purpose := range config.WorkloadPolicy.Purposes {
		pngBoundProfilePurpose(t, &config, purpose)
	}
	digest, err := engine.DomainProvisioningProfileDigest(*config.ProvisioningProfile)
	if err != nil {
		t.Fatal(err)
	}
	config.ProvisioningProfile.ProfileRef.ProfileDigest = digest
	return config
}

func pngBoundPolicy(t *testing.T) *engine.DomainWorkloadPolicy {
	t.Helper()
	p := &engine.DomainWorkloadPolicy{ContractRevision: pngBoundPolicyRevision, InstallationID: "LABELLED-installation", Issuer: pngWorkloadIssuer, MaxLifetimeSeconds: 30, Purposes: map[string]engine.DomainWorkloadPurpose{}}
	p.Purposes["messaging.sync"] = engine.DomainWorkloadPurpose{Provider: "alive5", Families: map[string]engine.DomainWorkloadFamily{
		"resource:png.messages": pngBoundFamily("png_record", "alive5.messages/1", "account_id direction id text", ""),
		pngWorkloadThreads:      pngBoundFamily("png_record", "alive5.conversations/1", "account_id id is_archived last_message title updated_at", "last_message title updated_at"),
		pngWorkloadContacts:     pngBoundFamily("png_record", "alive5.contacts/1", "account_id email id phone", "email phone"),
	}}
	p.Purposes["accounting.sync"] = engine.DomainWorkloadPurpose{Provider: "quickbooks", Families: map[string]engine.DomainWorkloadFamily{
		"resource:png_import": pngBoundFamily("png_record", "quickbooks.observation/1", "account_id attributes id", "attributes"),
		"business:associate":  pngBoundFamily("associate", "quickbooks.client/1", "account_id full_name id is_active quickbooks_id type", "full_name is_active quickbooks_id type"),
		"business:job":        pngBoundFamily("png_record", "quickbooks.project/1", "account_id client_id id quickbooks_id title", "client_id quickbooks_id title"),
	}}
	for name, purpose := range p.Purposes {
		raw, err := engine.CanonicalDomainJSON(map[string]interface{}{"contractRevision": p.ContractRevision, "installationId": p.InstallationID, "purpose": name, "provider": purpose.Provider, "families": purpose.Families})
		if err != nil {
			t.Fatal(err)
		}
		purpose.PolicyDigest = domainFixtureSHA(string(raw))
		p.Purposes[name] = purpose
	}
	return p
}

func pngBoundFamily(kind, rule, create, update string) engine.DomainWorkloadFamily {
	fields := strings.Fields(create)
	updates := strings.Fields(update)
	if updates == nil {
		updates = []string{}
	}
	sort.Strings(fields)
	sort.Strings(updates)
	return engine.DomainWorkloadFamily{Kind: kind, Rule: rule, ReadFields: append([]string{}, fields...), CreateFields: fields, UpdateFields: updates}
}

func pngBoundProfilePurpose(t *testing.T, config *DomainConfig, purpose engine.DomainWorkloadPurpose) {
	t.Helper()
	for _, kind := range []string{"root", "png_record", "associate"} {
		pngBoundProfileKind(config, purpose, kind)
	}
}

func pngBoundProfileKind(config *DomainConfig, purpose engine.DomainWorkloadPurpose, kind string) {
	profile := config.ProvisioningProfile
	extra := []string{"id", "pngKey", "pngFamily", "pngData", "pngVersion"}
	for family, rule := range purpose.Families {
		if kind != "root" && kind != rule.Kind {
			continue
		}
		extra = append(extra, "family."+family)
		for _, field := range rule.ReadFields {
			extra = append(extra, "data."+field)
		}
	}
	for _, op := range []string{"png.store.read", pngstore.WriteOperation} {
		fields := append(append([]string{}, extra...), profile.Layout.Profiles[op][kind]...)
		profile.Layout.Profiles[op][kind] = pngBoundUnique(fields)
		grant := profile.OwnerGrants[kind][op]
		grant.Fields = profile.Layout.Profiles[op][kind]
		profile.OwnerGrants[kind][op] = grant
	}
}

func pngBoundUnique(fields []string) []string {
	sort.Strings(fields)
	result := []string{}
	for _, field := range fields {
		if len(result) == 0 || result[len(result)-1] != field {
			result = append(result, field)
		}
	}
	return result
}

func pngBoundStart(t *testing.T) *pngBoundRun {
	t.Helper()
	config := pngBoundConfig(t)
	artifact := pngACLReadArtifact(t, pngWorkloadArtifact)
	_ = engine.DecodeDomainJSON(domainFixtureJSON(t, config.ProvisioningProfile.OwnerGrants), &artifact.Grants)
	base := &pngACLRun{t: t, config: config, artifact: artifact, directory: t.TempDir(), scope: engine.DomainScope{AccountID: "LABELLED-bound-workload-account", Product: "manifest"}}
	domain := &pngFixtureAuthority{config: &base.config, tickets: map[string]engine.DomainVerified{}, current: true}
	authority := &pngACLAuthority{pngEnrolledAuthority: pngEnrolledAuthority{domain: domain, consumed: map[string]bool{}}, targetRevision: "LABELLED-G1"}
	bound := &pngBoundAuthority{authority, map[string]engine.DomainWorkloadGrant{}, map[string]engine.DomainWorkloadRun{}}
	callback := httptest.NewServer(http.HandlerFunc(bound.check))
	t.Cleanup(callback.Close)
	base.config.Trust.VerifierEndpoint = callback.URL + "/internal/manifest-domain/check"
	base.authority = authority
	base.handle = openPNGFixture(t, base.directory, base.config)
	run := &pngBoundRun{&pngWorkloadRun{pngACLRun: base}, bound}
	t.Cleanup(func() { closePNGFixture(t, run.handle) })
	run.provision()
	return run
}

func (a *pngBoundAuthority) check(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1000001))
	var shape map[string]json.RawMessage
	if err != nil || len(raw) > 1000000 || engine.DecodeDomainJSON(raw, &shape) != nil || r.Header.Get("Authorization") != "Bearer "+a.domain.config.Trust.ChannelToken {
		w.WriteHeader(403)
		return
	}
	if shape["request"] != nil {
		a.enrollment(w, raw)
		return
	}
	var check engine.DomainCheck
	if engine.DecodeDomainJSON(raw, &check) != nil || !a.currentRun(check) {
		w.WriteHeader(403)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	a.domain.check(w, r)
}

func (a *pngBoundAuthority) currentRun(check engine.DomainCheck) bool {
	if check.Intent.Workload == nil {
		return check.ContractRevision == engine.DomainRevision
	}
	a.domain.mu.Lock()
	defer a.domain.mu.Unlock()
	principal := pngBoundPrincipal(check.Intent.Workload.Grant)
	return check.ContractRevision == pngBoundHandoffRevision && pngFixtureEqual(a.grants[principal], check.Intent.Workload.Grant) && pngFixtureEqual(a.runs[principal], *check.Intent.Workload)
}

func (a *pngBoundAuthority) enrollment(w http.ResponseWriter, raw []byte) {
	var check engine.EnrollmentCheck
	if engine.DecodeDomainJSON(raw, &check) != nil {
		w.WriteHeader(403)
		return
	}
	a.domain.mu.Lock()
	defer a.domain.mu.Unlock()
	if !a.enrollmentCurrent(check) {
		w.WriteHeader(403)
		return
	}
	a.consumed[check.Proof] = true
	actor := a.actor(check)
	value := map[string]interface{}{}
	encoded, _ := engine.CanonicalDomainJSON(actor)
	_ = engine.DecodeDomainJSON(encoded, &value)
	if check.ContractRevision == engine.EnrollmentBoundWorkloadProofRevision {
		value["administratorAuthorized"] = false
	}
	_ = json.NewEncoder(w).Encode(value)
}

func (a *pngBoundAuthority) enrollmentCurrent(check engine.EnrollmentCheck) bool {
	if a.consumed[check.Proof] || check.ContractRevision != a.input.ContractRevision || check.RequestID != a.input.RequestID || check.Audience != a.domain.config.Trust.Audience || !pngFixtureEqual(check.Request, a.input.Request) {
		return false
	}
	if g := check.Request.WorkloadGrant; g != nil && !pngFixtureEqual(a.grants[pngBoundPrincipal(*g)], *g) {
		return false
	}
	if check.Phase == "admission" {
		return check.Proof == a.input.Proof && check.LeaseBinding == nil
	}
	return check.Phase == "handoff" && check.Proof == a.input.Proof+"_handoff" && a.lease != nil && pngFixtureEqual(check.LeaseBinding, a.lease)
}

func pngBoundPrincipal(g engine.DomainWorkloadGrant) string {
	raw, _ := engine.CanonicalDomainJSON(map[string]string{"installationId": g.InstallationID, "accountId": g.AccountID, "connectionId": g.ConnectionID, "provider": g.Provider, "purpose": g.Purpose})
	return "workload:" + domainFixtureSHA(string(raw))
}

func (run *pngBoundRun) grant(purpose string) engine.DomainWorkloadRun {
	run.t.Helper()
	p := run.config.WorkloadPolicy
	g := engine.DomainWorkloadGrant{ContractRevision: pngBoundGrantRevision, InstallationID: p.InstallationID, AccountID: run.scope.AccountID, ConnectionID: "LABELLED-connection", Provider: p.Purposes[purpose].Provider, Purpose: purpose, GrantRevision: "LABELLED-G1", PolicyDigest: p.Purposes[purpose].PolicyDigest, ExpiresAt: 4102444800}
	w := engine.DomainWorkloadRun{ContractRevision: pngBoundRunRevision, Grant: g, RunID: "LABELLED-run", FenceGeneration: "1"}
	if err := run.changeGrant(g, engine.EnrollmentWorkloadGrant); err != nil {
		run.t.Fatal(err)
	}
	run.activate(w)
	return w
}

func (run *pngBoundRun) activate(w engine.DomainWorkloadRun) {
	run.bound.domain.mu.Lock()
	defer run.bound.domain.mu.Unlock()
	run.bound.runs[pngBoundPrincipal(w.Grant)] = w
}

func (run *pngBoundRun) changeGrant(g engine.DomainWorkloadGrant, operation string) error {
	run.sequence++
	target := pngBoundPrincipal(g)
	tag := fmt.Sprintf("LABELLED_bound_enrollment_%d", run.sequence)
	input := engine.EnrollmentInput{ContractRevision: engine.EnrollmentBoundWorkloadProofRevision, RequestID: tag, Proof: tag, Request: engine.EnrollmentRequest{ContractRevision: engine.EnrollmentBoundWorkloadRevision, Scope: run.scope, CommandID: tag, ExpectedRevision: run.revision, Operation: operation, TargetPrincipalID: &target, ProfileRef: run.config.ProvisioningProfile.ProfileRef, WorkloadGrant: &g}}
	run.bound.domain.mu.Lock()
	run.bound.grants[target] = g
	delete(run.bound.runs, target)
	run.bound.input, run.bound.lease, run.bound.targetRevision = input, nil, g.GrantRevision
	run.bound.domain.mu.Unlock()
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

func (run *pngBoundRun) issueBound(intent engine.DomainIntent, phase string, lease *engine.DomainLease) string {
	authority := run.bound.domain
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.sequence++
	token := fmt.Sprintf("LABELLED_bound_ticket_%d", authority.sequence)
	w := *intent.Workload
	principal := pngBoundPrincipal(w.Grant)
	actor := engine.DomainVerified{ContractRevision: pngBoundHandoffRevision, PrincipalID: principal, Kind: "workload", SessionID: "workload-session:" + strings.TrimPrefix(principal, "workload:") + ":" + w.RunID, Scope: intent.Scope, Intent: intent, Workload: &w, GrantRevision: w.Grant.GrantRevision, AuthorityResourceRevision: "LABELLED-current", ExpiresAt: float64(time.Now().Unix()) + 20, Issuer: pngWorkloadIssuer, Audience: authority.config.Trust.Audience, Phase: phase, LeaseBinding: lease, ProofBinding: domainFixtureSHA(token)}
	authority.tickets[token] = actor
	return token
}

func (run *pngBoundRun) beginBound(w engine.DomainWorkloadRun, request pngstore.Request, mode string) (pngFixtureExchange, error) {
	input := pngFixtureInput(run.t, request, mode)
	input.Workload = &w
	raw, err := run.handle.DomainResolve(domainFixtureJSON(run.t, input))
	if err != nil {
		return pngFixtureExchange{}, err
	}
	var intent engine.DomainIntent
	if err = engine.DecodeDomainJSON(raw, &intent); err != nil {
		return pngFixtureExchange{}, err
	}
	proof := run.issueBound(intent, "admission", nil)
	raw, err = run.handle.DomainCall(domainFixtureJSON(run.t, DomainRequest{DomainInput: input, RequestID: "LABELLED-bound-request", Proof: proof}))
	if err != nil {
		return pngFixtureExchange{}, err
	}
	var begin engine.DomainBegin
	if err = engine.DecodeDomainJSON(raw, &begin); err != nil {
		return pngFixtureExchange{}, err
	}
	_ = domainFixtureControlCall(run.t, domainFixtureControl(run.config, begin, "adopt"))
	var received engine.DomainReceived
	if err = engine.DecodeDomainJSON(domainFixtureControlCall(run.t, domainFixtureControl(run.config, begin, "receive")), &received); err != nil {
		return pngFixtureExchange{}, err
	}
	var body map[string]interface{}
	if err = engine.DecodeDomainJSON(received.Body, &body); err != nil {
		return pngFixtureExchange{}, err
	}
	return pngFixtureExchange{begin, received, intent, body}, nil
}

func (run *pngBoundRun) finishBound(exchange pngFixtureExchange) error {
	input := domainFixtureControl(run.config, exchange.begin, "handoff")
	input.Proof = run.issueBound(exchange.intent, "handoff", &exchange.begin.Lease)
	raw, err := DomainControlCall(domainFixtureJSON(run.t, input))
	if err != nil {
		run.discardBound(exchange)
		return err
	}
	var permit engine.DomainPermit
	if err = engine.DecodeDomainJSON(raw, &permit); err != nil {
		return err
	}
	input = domainFixtureControl(run.config, exchange.begin, "finish")
	input.ResponseHash, input.Disposition, input.PermitID = exchange.begin.ResponseHash, "handed-off", permit.PermitID
	raw, err = DomainControlCall(domainFixtureJSON(run.t, input))
	if err != nil {
		return err
	}
	var ack struct {
		Completed bool `json:"completed"`
	}
	if engine.DecodeDomainJSON(raw, &ack) != nil || !ack.Completed {
		return fmt.Errorf("actual terminal ACK missing")
	}
	if exchange.received.Pair != nil {
		run.revision = exchange.received.Pair.Revision
	}
	return nil
}

func (run *pngBoundRun) discardBound(exchange pngFixtureExchange) {
	input := domainFixtureControl(run.config, exchange.begin, "finish")
	input.ResponseHash, input.Disposition = exchange.begin.ResponseHash, "irrevocably-discarded"
	_ = domainFixtureControlCall(run.t, input)
}

func (run *pngBoundRun) asBound(w engine.DomainWorkloadRun, request pngstore.Request, mode string) (map[string]interface{}, error) {
	exchange, err := run.beginBound(w, request, mode)
	if err != nil {
		return nil, err
	}
	if mode == "command" && exchange.received.Pair == nil {
		run.discardBound(exchange)
		return nil, fmt.Errorf("command has no actual paired receipt")
	}
	if err = run.finishBound(exchange); err != nil {
		return nil, err
	}
	return exchange.body, nil
}
