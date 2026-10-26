// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

func enrollmentRecord(actor EnrollmentVerified) (enrollmentRecordValue, error) {
	r := enrollmentRecordValue{ContractRevision: enrollmentRecordRevision(actor.Request), Request: actor.Request, RequestID: actor.RequestID, PrincipalID: actor.PrincipalID, SessionID: actor.SessionID, RequestFingerprint: actor.RequestFingerprint, GrantRevision: actor.GrantRevision, AuthorityPolicyRevision: actor.AuthorityPolicyRevision, AuthorityResourceRevision: actor.AuthorityResourceRevision, PrincipalReference: actor.PrincipalReference}
	if actor.PrincipalReference != nil {
		r.TargetGrantRevision = actor.PrincipalReference.TargetGrantRevision
	}
	if !enrollmentActorAuthorized(actor) || actor.Purpose != actor.Request.Operation {
		return r, fmt.Errorf("verified current human owner required for enrollment provenance")
	}
	raw, err := CanonicalDomainJSON(r)
	if err == nil {
		err = validateEnrollmentRecord(r, len(raw))
	}
	return r, err
}

func decodeEnrollmentRecord(raw []byte, maximum int) (enrollmentRecordValue, error) {
	var record enrollmentRecordValue
	if maximum <= 0 || len(raw) == 0 || len(raw) > maximum {
		return record, fmt.Errorf("bounded actual enrollment provenance required")
	}
	keys := []string{"contractRevision", "request", "requestId", "principalId", "sessionId", "requestFingerprint", "grantRevision", "authorityPolicyRevision", "authorityResourceRevision", "principalReference", "targetGrantRevision"}
	shape, err := enrollmentShape(raw, keys, nil, []string{"principalReference", "targetGrantRevision"})
	if err != nil {
		return record, err
	}
	if !enrollmentNull(shape["principalReference"]) {
		if err = enrollmentReferenceShape(shape["principalReference"]); err != nil {
			return record, err
		}
	}
	if err = DecodeDomainJSON(raw, &record); err != nil {
		return record, err
	}
	return record, validateEnrollmentRecord(record, maximum)
}

func validateEnrollmentRecord(record enrollmentRecordValue, maximum int) error {
	raw, err := canonicalEnrollmentRequest(record.Request, maximum)
	if err != nil || record.ContractRevision != enrollmentRecordRevision(record.Request) || record.RequestFingerprint != stagedHash(raw) {
		return fmt.Errorf("enrollment provenance request revision/fingerprint mismatch")
	}
	if err = enrollmentIdentifiers(maximum, record.PrincipalID, record.SessionID, record.RequestID, record.GrantRevision, record.AuthorityPolicyRevision, record.AuthorityResourceRevision); err != nil {
		return err
	}
	ref := record.PrincipalReference
	if record.Request.Operation == EnrollmentProvision {
		if ref != nil || record.TargetGrantRevision != nil {
			return fmt.Errorf("provision provenance must not contain target authority")
		}
		return nil
	}
	if ref == nil || record.Request.TargetPrincipalID == nil || !domainEqual(record.TargetGrantRevision, ref.TargetGrantRevision) {
		return fmt.Errorf("exact historical target revision required")
	}
	if ref.ActorPrincipalID != record.PrincipalID || ref.ActorSessionID != record.SessionID || ref.ActorGrantRevision != record.GrantRevision || ref.AccountID != record.Request.Scope.AccountID || ref.PrincipalID != *record.Request.TargetPrincipalID || ref.PrincipalID == record.PrincipalID || ref.Purpose != record.Request.Operation || ref.RequestID != record.RequestID || ref.AuthorityPolicyRevision != record.AuthorityPolicyRevision {
		return fmt.Errorf("enrollment provenance actor/target correlation mismatch")
	}
	return validateEnrollmentHistoricalTarget(record, maximum)
}

func validateEnrollmentHistoricalTarget(record enrollmentRecordValue, maximum int) error {
	ref := record.PrincipalReference
	if enrollmentIdentifiers(maximum, ref.PrincipalID, ref.EvidenceRevision, ref.AuthorityPolicyRevision) != nil || !domainFinite(ref.CheckedAt) || !domainFinite(ref.ValidUntil) || ref.CheckedAt <= 0 || ref.ValidUntil <= ref.CheckedAt {
		return fmt.Errorf("invalid historical target provenance")
	}
	if ref.TargetEligibility == "active" && ref.TargetGrantRevision != nil {
		return enrollmentIdentifiers(maximum, *ref.TargetGrantRevision)
	}
	if record.Request.Operation == EnrollmentReadRevoke && ref.TargetEligibility == "revoked" && ref.TargetGrantRevision == nil {
		return nil
	}
	return fmt.Errorf("unaccepted target provenance cannot grant access")
}

func validateEnrollmentReceipt(binding stagedBinding, receipt stagedReceipt, maximum int) error {
	enrollment := isEnrollmentOperation(receipt.Command.Action)
	if len(receipt.EnrollmentRecord) == 0 {
		if enrollment {
			return fmt.Errorf("actual enrollment receipt requires typed provenance")
		}
		return nil
	}
	if !enrollment || len(receipt.ProductIntent)+len(receipt.MappingRecord) != 0 {
		return fmt.Errorf("mixed/unrelated enrollment receipt grammar denied")
	}
	record, err := decodeEnrollmentRecord(receipt.EnrollmentRecord, maximum)
	if err != nil {
		return err
	}
	r, c := record.Request, receipt.Command
	if binding.ProductID != "manifest" || binding.AccountID != r.Scope.AccountID || binding.ScopeID != enrollmentScopeID(r.Scope.AccountID) || c != (enrollmentCommand(EnrollmentVerified{PrincipalID: record.PrincipalID, Request: r, RequestFingerprint: record.RequestFingerprint}, binding)) {
		return fmt.Errorf("enrollment receipt command/account/scope identity mismatch")
	}
	if receipt.Version != 1 || receipt.Fingerprint != stagedCommandFingerprint(binding, c) || !validEnrollmentOwnedRevision(receipt.AfterRevision) {
		return fmt.Errorf("enrollment receipt fingerprint/revision mismatch")
	}
	return validateEnrollmentTargets(binding, receipt, maximum)
}

func validateEnrollmentTargets(binding stagedBinding, receipt stagedReceipt, maximum int) error {
	if len(receipt.Targets) == 0 || len(receipt.Targets) > maximum {
		return fmt.Errorf("actual bounded enrollment ACL targets required")
	}
	if receipt.Command.Action == EnrollmentProvision && (len(receipt.Targets) != 1 || receipt.Targets[0].NodeID != binding.RootID || !domainEqual(receipt.Targets[0].Fields, []string{"acl"})) {
		return fmt.Errorf("provision receipt must target only fresh root ACL")
	}
	seen, root, field := map[string]bool{}, false, ""
	for _, target := range receipt.Targets {
		if len(target.Fields) != 1 || enrollmentIdentifiers(maximum, target.NodeID, target.Kind, target.Fields[0]) != nil || seen[target.NodeID] {
			return fmt.Errorf("unique ACL-only enrollment receipt targets required")
		}
		if field != "" && field != target.Fields[0] {
			return fmt.Errorf("enrollment targets must use one protected ACL metadata key")
		}
		field, seen[target.NodeID] = target.Fields[0], true
		root = root || target.NodeID == binding.RootID
	}
	if !root {
		return fmt.Errorf("enrollment receipt must bind actual root")
	}
	return nil
}

func isEnrollmentOperation(operation string) bool {
	return operation == EnrollmentProvision || operation == EnrollmentReadGrant || operation == EnrollmentReadRevoke
}

// Historical sessions/request ids are provenance, not replay authority.
func validateEnrollmentReplayActor(record enrollmentRecordValue, actor EnrollmentVerified) error {
	if record.PrincipalID != actor.PrincipalID || !domainEqual(record.Request, actor.Request) || record.RequestFingerprint != actor.RequestFingerprint || record.GrantRevision != actor.GrantRevision || record.AuthorityPolicyRevision != actor.AuthorityPolicyRevision || record.AuthorityResourceRevision != actor.AuthorityResourceRevision {
		return fmt.Errorf("original enrollment owner claim/policy/request revoked or replaced")
	}
	if !enrollmentReplayTargetSame(record.PrincipalReference, actor.PrincipalReference) {
		return fmt.Errorf("original enrollment target authority revoked or replaced")
	}
	return nil
}

func enrollmentReplayTargetSame(old, current *DomainPrincipalReference) bool {
	if old == nil || current == nil {
		return old == nil && current == nil
	}
	copy := *old
	copy.ActorSessionID, copy.RequestID = current.ActorSessionID, current.RequestID
	copy.CheckedAt, copy.ValidUntil = current.CheckedAt, current.ValidUntil
	return domainEqual(copy, *current)
}
