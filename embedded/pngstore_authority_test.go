// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"encoding/json"
	"fmt"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type pngFixtureAuthority struct {
	mu       sync.Mutex
	config   *DomainConfig
	tickets  map[string]engine.DomainVerified
	current  bool
	sequence int
	accepted int
}

func pngFixtureVerifier(t *testing.T, config *DomainConfig) *pngFixtureAuthority {
	authority := &pngFixtureAuthority{config: config, tickets: map[string]engine.DomainVerified{}, current: true}
	server := httptest.NewServer(http.HandlerFunc(authority.check))
	config.Trust.VerifierEndpoint = server.URL + "/internal/manifest-domain/check"
	t.Cleanup(server.Close)
	return authority
}
func (authority *pngFixtureAuthority) issue(intent engine.DomainIntent, phase string, lease *engine.DomainLease, principal string) string {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.sequence++
	token := fmt.Sprintf("png_fixture_ticket_%d", authority.sequence)
	actor := engine.DomainVerified{ContractRevision: engine.DomainRevision, PrincipalID: principal, Kind: "human", SessionID: "fixture-session", Scope: intent.Scope, Intent: intent, GrantRevision: "fixture-grant", AuthorityResourceRevision: "fixture-current", ExpiresAt: float64(time.Now().Unix()) + 30, Issuer: authority.config.Trust.Issuer, Audience: authority.config.Trust.Audience, Phase: phase, LeaseBinding: lease, ProofBinding: domainFixtureSHA(token)}
	authority.tickets[token] = actor
	return token
}
func (authority *pngFixtureAuthority) check(w http.ResponseWriter, request *http.Request) {
	var check engine.DomainCheck
	if request.Method != "POST" || request.Header.Get("Authorization") != "Bearer "+authority.config.Trust.ChannelToken || json.NewDecoder(request.Body).Decode(&check) != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	actor, present := authority.tickets[check.Proof]
	if !present || !authority.current || actor.Phase != check.Phase || actor.Audience != check.Audience || !pngFixtureEqual(actor.Intent, check.Intent) || !pngFixtureEqual(actor.LeaseBinding, check.LeaseBinding) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	delete(authority.tickets, check.Proof)
	authority.accepted++
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(actor)
}
func pngFixtureEqual(left, right interface{}) bool {
	first, err := engine.CanonicalDomainJSON(left)
	second, other := engine.CanonicalDomainJSON(right)
	return err == nil && other == nil && string(first) == string(second)
}
func (authority *pngFixtureAuthority) revoke() {
	authority.mu.Lock()
	authority.current = false
	authority.mu.Unlock()
}
func (authority *pngFixtureAuthority) acceptanceCount() int {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	return authority.accepted
}
