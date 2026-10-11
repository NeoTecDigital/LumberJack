// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"time"
)

var domainOpaqueProof = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func (d *domainEngine) verify(ctx context.Context, proof, phase string, intent DomainIntent, lease *DomainLease) (DomainVerified, error) {
	if len(proof) == 0 || len(proof) > d.config.Trust.MaxProofBytes || !domainOpaqueProof.MatchString(proof) {
		return DomainVerified{}, fmt.Errorf("domain proof denied")
	}
	check := DomainCheck{DomainRevision, proof, phase, d.config.Trust.Audience, intent, lease}
	body, err := CanonicalDomainJSON(check)
	if err != nil {
		return DomainVerified{}, err
	}
	if int64(len(body)) > d.config.Trust.MaxBodyBytes {
		return DomainVerified{}, fmt.Errorf("bounded proof check exceeded")
	}
	request, err := http.NewRequestWithContext(ctx, "POST", d.config.Trust.VerifierEndpoint, bytes.NewReader(body))
	if err != nil {
		return DomainVerified{}, err
	}
	request.Header.Set("Authorization", "Bearer "+d.config.Trust.ChannelToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := d.verifier.client.Do(request)
	if err != nil {
		return DomainVerified{}, fmt.Errorf("domain authority unavailable")
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, d.config.Trust.MaxResponseBytes+1))
	if err != nil || int64(len(answer)) > d.config.Trust.MaxResponseBytes || response.StatusCode != 200 {
		return DomainVerified{}, fmt.Errorf("domain authority denied/unavailable")
	}
	var actor DomainVerified
	if DecodeDomainJSON(answer, &actor) != nil || !d.validActor(actor, check) {
		return DomainVerified{}, fmt.Errorf("invalid domain authority")
	}
	return actor, nil
}
func (d *domainEngine) validActor(actor DomainVerified, check DomainCheck) bool {
	now := domainNow()
	owned, present := d.scopes[actor.Scope]
	if !present {
		return false
	}
	if validateStagedIdentifiers(owned.Bounds, actor.PrincipalID, actor.SessionID, actor.GrantRevision, actor.AuthorityResourceRevision) != nil {
		return false
	}
	if actor.ContractRevision != DomainRevision || actor.Kind != "human" || actor.PrincipalID == "" || actor.SessionID == "" || actor.GrantRevision == "" || actor.AuthorityResourceRevision == "" {
		return false
	}
	if actor.Issuer != d.config.Trust.Issuer || actor.Audience != check.Audience || actor.Phase != check.Phase || actor.ProofBinding != stagedHash([]byte(check.Proof)) {
		return false
	}
	if math.IsNaN(actor.ExpiresAt) || math.IsInf(actor.ExpiresAt, 0) || actor.ExpiresAt <= now || actor.ExpiresAt > now+float64(d.config.Trust.MaxLifetimeSeconds) {
		return false
	}
	return actor.Scope == check.Intent.Scope && domainEqual(actor.Intent, check.Intent) && domainEqual(actor.LeaseBinding, check.LeaseBinding)
}
func domainNow() float64 { return float64(time.Now().UnixNano()) / 1e9 }
