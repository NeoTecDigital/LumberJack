// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

func (d *domainEngine) verifyEnrollment(ctx context.Context, input EnrollmentInput, phase string, lease *DomainLease) (EnrollmentVerified, error) {
	if phase != "admission" && phase != "handoff" || (phase == "admission") != (lease == nil) {
		return EnrollmentVerified{}, fmt.Errorf("exact enrollment admission/handoff phase required")
	}
	if len(input.Proof) == 0 || len(input.Proof) > d.config.Trust.MaxProofBytes || !domainOpaqueProof.MatchString(input.Proof) {
		return EnrollmentVerified{}, fmt.Errorf("bounded opaque current enrollment proof required")
	}
	raw, err := canonicalEnrollmentRequest(input.Request, d.config.MaxRequestBytes)
	if err != nil {
		return EnrollmentVerified{}, err
	}
	check := EnrollmentCheck{enrollmentProofRevision(input.Request), input.Proof, phase, d.config.Trust.Audience, input.RequestID, input.Request, stagedHash(raw), lease}
	body, err := CanonicalDomainJSON(check)
	if err != nil || int64(len(body)) > d.config.Trust.MaxBodyBytes {
		return EnrollmentVerified{}, fmt.Errorf("bounded enrollment authority check exceeded")
	}
	answer, err := d.enrollmentCallback(ctx, body)
	if err != nil {
		return EnrollmentVerified{}, err
	}
	actor, err := decodeEnrollmentVerified(answer)
	if err != nil || !d.validEnrollmentActor(actor, check) || ctx.Err() != nil {
		return EnrollmentVerified{}, fmt.Errorf("current enrollment authority denied/invalid")
	}
	return actor, nil
}

func (d *domainEngine) enrollmentCallback(ctx context.Context, body []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, d.config.Trust.VerifierEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+d.config.Trust.ChannelToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := d.verifier.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("current enrollment authority unavailable")
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, d.config.Trust.MaxResponseBytes+1))
	if err != nil || int64(len(answer)) > d.config.Trust.MaxResponseBytes || response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("current enrollment authority denied/unavailable")
	}
	return answer, nil
}

func decodeEnrollmentVerified(raw []byte) (EnrollmentVerified, error) {
	var actor EnrollmentVerified
	keys := []string{"contractRevision", "principalId", "kind", "sessionId", "scope", "requestId", "request", "requestFingerprint", "grantRevision", "authorityPolicyRevision", "authorityResourceRevision", "expiresAt", "issuer", "audience", "phase", "leaseBinding", "proofBinding", "ownerAuthorized", "principalReference", "purpose"}
	keys = enrollmentAdministrationKeys(raw, keys, "administratorAuthorized")
	shape, err := enrollmentShape(raw, keys, nil, []string{"leaseBinding", "principalReference"})
	if err != nil {
		return actor, err
	}
	if _, err = enrollmentShape(shape["scope"], []string{"accountId", "product"}, nil, nil); err != nil {
		return actor, err
	}
	if !enrollmentNull(shape["principalReference"]) {
		if err = enrollmentReferenceShape(shape["principalReference"]); err != nil {
			return actor, err
		}
	}
	if !enrollmentNull(shape["leaseBinding"]) {
		if err = enrollmentLeaseShape(shape["leaseBinding"]); err != nil {
			return actor, err
		}
	}
	err = DecodeDomainJSON(raw, &actor)
	return actor, err
}

func (d *domainEngine) validEnrollmentActor(actor EnrollmentVerified, check EnrollmentCheck) bool {
	now := domainNow()
	p, err := d.enrollmentProfile(actor.Request)
	if err != nil || enrollmentIdentifiers(p.Bounds.MaxIdentifierBytes, actor.PrincipalID, actor.SessionID, actor.RequestID, actor.GrantRevision, actor.AuthorityPolicyRevision, actor.AuthorityResourceRevision) != nil {
		return false
	}
	if actor.ContractRevision != enrollmentProofRevision(check.Request) || !enrollmentActorAuthorized(actor) || actor.Purpose != check.Request.Operation {
		return false
	}
	if actor.Issuer != d.config.Trust.Issuer || actor.Audience != check.Audience || actor.Phase != check.Phase || actor.ProofBinding != stagedHash([]byte(check.Proof)) {
		return false
	}
	if actor.Scope != check.Request.Scope || actor.RequestID != check.RequestID || actor.RequestFingerprint != check.RequestFingerprint || !domainEqual(actor.Request, check.Request) || !domainEqual(actor.LeaseBinding, check.LeaseBinding) {
		return false
	}
	if !domainFinite(actor.ExpiresAt) || actor.ExpiresAt <= now || actor.ExpiresAt > now+float64(d.config.Trust.MaxLifetimeSeconds) {
		return false
	}
	if !validEnrollmentPhaseLease(actor, check, p.Bounds.MaxIdentifierBytes) {
		return false
	}
	return validEnrollmentTarget(actor, p.Bounds.MaxIdentifierBytes, now, float64(d.config.Trust.MaxLifetimeSeconds))
}

func validEnrollmentPhaseLease(actor EnrollmentVerified, check EnrollmentCheck, maximum int) bool {
	if check.Phase == "admission" {
		return check.LeaseBinding == nil
	}
	lease := check.LeaseBinding
	if check.Phase != "handoff" || lease == nil {
		return false
	}
	if enrollmentIdentifiers(maximum, lease.Epoch, lease.LeaseID, lease.Binding.RootID, lease.Binding.BindingRevision) != nil {
		return false
	}
	return lease.PrincipalID == actor.PrincipalID && lease.SessionID == actor.SessionID && lease.Scope == actor.Scope && lease.Binding.Scope == actor.Scope && lease.IntentFingerprint == actor.RequestFingerprint
}

func validEnrollmentTarget(actor EnrollmentVerified, maximum int, now, lifetime float64) bool {
	ref := actor.PrincipalReference
	if actor.Request.Operation == EnrollmentProvision {
		return ref == nil && actor.Request.TargetPrincipalID == nil
	}
	if ref == nil || actor.Request.TargetPrincipalID == nil || ref.PrincipalID == actor.PrincipalID {
		return false
	}
	if ref.ActorPrincipalID != actor.PrincipalID || ref.ActorSessionID != actor.SessionID || ref.ActorGrantRevision != actor.GrantRevision || ref.AccountID != actor.Scope.AccountID || ref.PrincipalID != *actor.Request.TargetPrincipalID || ref.Purpose != actor.Purpose || ref.RequestID != actor.RequestID || ref.AuthorityPolicyRevision != actor.AuthorityPolicyRevision {
		return false
	}
	if enrollmentIdentifiers(maximum, ref.PrincipalID, ref.EvidenceRevision, ref.AuthorityPolicyRevision) != nil {
		return false
	}
	if !domainFinite(ref.CheckedAt) || !domainFinite(ref.ValidUntil) || ref.CheckedAt > now || ref.CheckedAt < now-lifetime || ref.ValidUntil <= now || ref.ValidUntil > now+lifetime || actor.ExpiresAt > ref.ValidUntil {
		return false
	}
	if ref.TargetEligibility == "active" {
		return ref.TargetGrantRevision != nil && enrollmentIdentifiers(maximum, *ref.TargetGrantRevision) == nil
	}
	return actor.Request.Operation == EnrollmentReadRevoke && ref.TargetEligibility == "revoked" && ref.TargetGrantRevision == nil
}

// Only freshness/proof/phase may refresh within one admitted lease.
func enrollmentActorSame(old, current EnrollmentVerified) bool {
	old.Phase, old.ProofBinding, old.LeaseBinding, old.ExpiresAt = current.Phase, current.ProofBinding, current.LeaseBinding, current.ExpiresAt
	if old.PrincipalReference != nil && current.PrincipalReference != nil {
		copy := *old.PrincipalReference
		copy.CheckedAt, copy.ValidUntil = current.PrincipalReference.CheckedAt, current.PrincipalReference.ValidUntil
		old.PrincipalReference = &copy
	}
	return domainEqual(old, current)
}
