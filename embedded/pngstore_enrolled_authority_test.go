// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"bytes"
	"encoding/json"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type pngEnrolledAuthority struct {
	domain   *pngFixtureAuthority
	input    engine.EnrollmentInput
	lease    *engine.DomainLease
	consumed map[string]bool
	expires  float64
}

func pngEnrolledVerifier(t *testing.T, config *DomainConfig, input engine.EnrollmentInput) *pngEnrolledAuthority {
	authority := &pngEnrolledAuthority{domain: &pngFixtureAuthority{config: config, tickets: map[string]engine.DomainVerified{}, current: true}, input: input, consumed: map[string]bool{}, expires: float64(time.Now().Unix()) + 30}
	server := httptest.NewServer(http.HandlerFunc(authority.check))
	config.Trust.VerifierEndpoint = server.URL + "/internal/manifest-domain/check"
	t.Cleanup(server.Close)
	return authority
}
func (authority *pngEnrolledAuthority) check(w http.ResponseWriter, request *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(request.Body, 1000001))
	var shape map[string]json.RawMessage
	if err != nil || len(raw) > 1000000 || engine.DecodeDomainJSON(raw, &shape) != nil {
		w.WriteHeader(403)
		return
	}
	if shape["request"] == nil {
		request.Body = io.NopCloser(bytes.NewReader(raw))
		authority.domain.check(w, request)
		return
	}
	var check engine.EnrollmentCheck
	if engine.DecodeDomainJSON(raw, &check) != nil || request.Header.Get("Authorization") != "Bearer "+authority.domain.config.Trust.ChannelToken {
		w.WriteHeader(403)
		return
	}
	authority.domain.mu.Lock()
	defer authority.domain.mu.Unlock()
	if !authority.enrollmentAllowed(check) {
		w.WriteHeader(403)
		return
	}
	authority.consumed[check.Proof] = true
	actor := authority.enrollmentActor(check)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(actor)
}
func (authority *pngEnrolledAuthority) enrollmentAllowed(check engine.EnrollmentCheck) bool {
	if authority.consumed[check.Proof] || check.ContractRevision != engine.EnrollmentProofRevision || check.RequestID != authority.input.RequestID || !pngFixtureEqual(check.Request, authority.input.Request) {
		return false
	}
	if check.Audience != authority.domain.config.Trust.Audience {
		return false
	}
	if check.Phase == "admission" {
		return check.Proof == authority.input.Proof && check.LeaseBinding == nil
	}
	return check.Phase == "handoff" && check.Proof == authority.input.Proof+"_handoff" && authority.lease != nil && pngFixtureEqual(check.LeaseBinding, authority.lease)
}
func (authority *pngEnrolledAuthority) enrollmentActor(check engine.EnrollmentCheck) engine.EnrollmentVerified {
	config := authority.domain.config
	actor := engine.EnrollmentVerified{ContractRevision: engine.EnrollmentProofRevision, PrincipalID: "fixture-human", Kind: "human", SessionID: "fixture-session", Scope: check.Request.Scope, RequestID: check.RequestID, Request: check.Request, RequestFingerprint: check.RequestFingerprint, GrantRevision: "fixture-grant", AuthorityPolicyRevision: "explicit-synthetic-policy", AuthorityResourceRevision: "explicit-pending-owner-resource", ExpiresAt: authority.expires, Issuer: config.Trust.Issuer, Audience: check.Audience, Phase: check.Phase, LeaseBinding: check.LeaseBinding, ProofBinding: domainFixtureSHA(check.Proof), OwnerAuthorized: true, Purpose: check.Request.Operation}
	if target := check.Request.TargetPrincipalID; target != nil {
		revision := "fixture-grant"
		actor.PrincipalReference = &engine.DomainPrincipalReference{ActorPrincipalID: actor.PrincipalID, ActorSessionID: actor.SessionID, AccountID: actor.Scope.AccountID, PrincipalID: *target, Purpose: actor.Purpose, RequestID: actor.RequestID, ActorGrantRevision: actor.GrantRevision, TargetGrantRevision: &revision, EvidenceRevision: "fixture-accepted-target", AuthorityPolicyRevision: actor.AuthorityPolicyRevision, CheckedAt: float64(time.Now().Unix()) - 1, ValidUntil: authority.expires + 10, TargetEligibility: "active"}
	}
	return actor
}
