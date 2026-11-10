// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

type coownerACLEffect struct {
	NodeID string      `json:"nodeId"`
	Before interface{} `json:"before"`
	After  interface{} `json:"after"`
}

func coownerContributionValue(acl domainACL, target string) interface{} {
	var current *domainCoownerContribution
	if c, present := acl.Coowners[target]; present {
		copy := c
		current = &copy
	}
	templates := map[string]interface{}{}
	for kind, template := range acl.CreateACLs {
		templates[kind] = coownerContributionValue(template, target)
	}
	return map[string]interface{}{"contribution": current, "templates": templates}
}

func coownerEffectDigest(effects []coownerACLEffect, followers map[string]int) string {
	return coownerHash(map[string]interface{}{"effects": effects, "followers": followers})
}

func coownerHash(value interface{}) string {
	raw, err := CanonicalDomainJSON(value)
	if err != nil {
		return ""
	}
	return stagedHash(raw)
}

func coownerRecord(actor EnrollmentVerified, effect string) (enrollmentRecordValue, error) {
	r := enrollmentRecordValue{ContractRevision: EnrollmentCoownerRecordRevision, Request: actor.Request, RequestID: actor.RequestID, PrincipalID: actor.PrincipalID, SessionID: actor.SessionID, RequestFingerprint: actor.RequestFingerprint, GrantRevision: actor.GrantRevision, AuthorityPolicyRevision: actor.AuthorityPolicyRevision, AuthorityResourceRevision: actor.AuthorityResourceRevision, PrincipalReference: actor.PrincipalReference, CoownerAuthority: actor.CoownerAuthority, ACLEffectDigest: effect}
	if actor.PrincipalReference != nil {
		r.TargetGrantRevision = actor.PrincipalReference.TargetGrantRevision
	}
	if !coownerActorAuthorized(actor) {
		return r, fmt.Errorf("current co-owner mutation provenance required")
	}
	raw, err := CanonicalDomainJSON(r)
	if err == nil {
		err = validateEnrollmentRecord(r, len(raw))
	}
	return r, err
}

func validateCoownerRecord(record enrollmentRecordValue) error {
	if !enrollmentCoownerRequest(record.Request) {
		if record.CoownerAuthority != nil || record.ACLEffectDigest != "" {
			return fmt.Errorf("legacy record cannot carry co-owner provenance")
		}
		return nil
	}
	a := record.CoownerAuthority
	if a == nil || a.ReceiptAuthorized || a.AccountKind != "organization" || a.TargetKind != "human" || !a.TargetAccepted || enrollmentIdentifiers(4096, a.CommandRevision) != nil || !domainValidHash(record.ACLEffectDigest) {
		return fmt.Errorf("exact co-owner authority/effect provenance required")
	}
	if !domainContains([]string{"confirmed", "revoking", "revoked"}, a.TargetNativeState) || a.ActorGrantState != "active" && !(a.ActorGrantState == "revoking" && record.Request.Operation == EnrollmentCoownerRevoke && *record.Request.TargetPrincipalID == record.PrincipalID) {
		return fmt.Errorf("invalid historical co-owner authority state")
	}
	if record.Request.Operation == EnrollmentCoownerGrant && a.TargetNativeState != "confirmed" {
		return fmt.Errorf("co-owner grant requires confirmed target provenance")
	}
	if !domainEqual(record.TargetGrantRevision, record.Request.CoownerChange.ExpectedTargetGrantRevision) {
		return fmt.Errorf("historical current target revision differs from reserved change")
	}
	return nil
}

func coownerOwnerRevision(r EnrollmentRequest) string {
	if r.Operation == EnrollmentCoownerGrant {
		return *r.CoownerChange.OwnerGrantRevision
	}
	return *r.CoownerChange.ExpectedCoownerGrantRevision
}

func coownerNativeState(r EnrollmentRequest) string {
	if r.Operation == EnrollmentCoownerGrant {
		return "installed"
	}
	return "revoked"
}

func coownerReceiptFields(r EnrollmentRequest, revision, fingerprint, effect string, binding DomainBinding) map[string]interface{} {
	return map[string]interface{}{"commandId": r.CommandID, "operation": r.Operation, "expectedRevision": r.ExpectedRevision, "requestFingerprint": fingerprint, "revision": revision, "binding": binding, "profileRef": r.ProfileRef, "targetPrincipalId": *r.TargetPrincipalID, "coownerChange": r.CoownerChange, "nativeCoownerState": coownerNativeState(r), "ownerGrantRevision": coownerOwnerRevision(r), "aclEffectDigest": effect}
}

func coownerPublicResponse(entry *domainEntry, revision, status string) ([]byte, error) {
	r := entry.enrollment.input.Request
	receipt := coownerReceiptFields(r, revision, coownerRequestFingerprint(r), entry.enrollment.effectDigest, entry.lease.Binding)
	receipt["status"] = status
	return CanonicalDomainJSON(map[string]interface{}{"contractRevision": r.ContractRevision, "requestId": entry.enrollment.input.RequestID, "scope": r.Scope, "receipt": receipt})
}
