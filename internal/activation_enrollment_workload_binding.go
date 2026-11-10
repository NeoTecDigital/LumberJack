// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
)

const EnrollmentBoundWorkloadRevision = "manifest-account-enrollment/0.5"
const EnrollmentBoundWorkloadProofRevision = "manifest-native-enrollment/0.5"
const EnrollmentBoundWorkloadRecordRevision = "manifest-native-enrollment-record/0.5"

func boundWorkloadEnrollment(r EnrollmentRequest) bool {
	return r.ContractRevision == EnrollmentBoundWorkloadRevision
}

func workloadEnrollmentKeys(raw []byte, keys []string) []string {
	var revision struct {
		ContractRevision string `json:"contractRevision"`
	}
	_ = json.Unmarshal(raw, &revision)
	if revision.ContractRevision == EnrollmentBoundWorkloadRevision {
		return append(keys, "workloadGrant")
	}
	return keys
}

func (r EnrollmentRequest) MarshalJSON() ([]byte, error) {
	type plain EnrollmentRequest
	raw, err := json.Marshal(plain(r))
	if err != nil || !boundWorkloadEnrollment(r) {
		return raw, err
	}
	var shape map[string]json.RawMessage
	if err = json.Unmarshal(raw, &shape); err != nil {
		return nil, err
	}
	shape["administration"], err = json.Marshal(r.Administration)
	if err != nil {
		return nil, err
	}
	return json.Marshal(shape)
}

func validateBoundWorkloadEnrollment(r EnrollmentRequest, maximum int) error {
	g := r.WorkloadGrant
	if !isEnrollmentWorkloadOperation(r.Operation) || g == nil || validateWorkloadGrant(*g) != nil || g.AccountID != r.Scope.AccountID || r.TargetPrincipalID == nil || *r.TargetPrincipalID != workloadPrincipal(*g) || r.CoownerChange != nil || !validEnrollmentOwnedRevision(r.ExpectedRevision) {
		return fmt.Errorf("exact bound workload enrollment tuple/CAS required")
	}
	if r.Administration == nil {
		return nil
	}
	return validateEnrollmentAdministrationRequest(r, maximum)
}

func (d *domainEngine) validBoundWorkloadEnrollment(actor EnrollmentVerified) bool {
	r, p := actor.Request, d.config.WorkloadPolicy
	if validateBoundWorkloadEnrollment(r, d.config.MaxRequestBytes) != nil || p == nil || p.ContractRevision != domainWorkloadPolicyRevision || r.WorkloadGrant.InstallationID != p.InstallationID {
		return false
	}
	if r.Operation == EnrollmentWorkloadGrant {
		_, err := workloadPurposeForGrant(p, *r.WorkloadGrant, true)
		return err == nil
	}
	return true // Exact installed G may be expired or its former policy disabled.
}

func workloadEnrollmentReference(r EnrollmentRequest, ref *DomainPrincipalReference) bool {
	if !boundWorkloadEnrollment(r) {
		return true
	}
	if r.WorkloadGrant == nil || ref == nil || r.TargetPrincipalID == nil || *r.TargetPrincipalID != workloadPrincipal(*r.WorkloadGrant) {
		return false
	}
	if ref.TargetEligibility == "active" {
		return ref.TargetGrantRevision != nil && *ref.TargetGrantRevision == r.WorkloadGrant.GrantRevision
	}
	return r.Operation == EnrollmentWorkloadRevoke && ref.TargetEligibility == "revoked" && ref.TargetGrantRevision == nil
}

func boundEnrollmentWorkloadGrants(d *domainEngine, entry *domainEntry, kind string) (map[string]domainGrant, error) {
	g := entry.enrollment.actor.Request.WorkloadGrant
	purpose, err := workloadPurposeForGrant(d.config.WorkloadPolicy, *g, true)
	if err != nil {
		return nil, err
	}
	grants := map[string]domainGrant{}
	for _, operation := range []string{domainStoreReadOperation, nativeStoreCommand} {
		fields, err := boundWorkloadGrantFields(purpose, entry.owned.Layout, operation, kind)
		if err != nil {
			return nil, err
		}
		copy := *g
		grant := domainGrant{Fields: fields, TargetGrantRevision: g.GrantRevision, WorkloadGrant: &copy}
		if kind == "root" && operation == nativeStoreCommand {
			grant.CreateKinds = domainWithout(workloadPurposeKinds(purpose), "root")
		}
		grants[operation] = grant
	}
	return grants, nil
}

func boundWorkloadListGrant(acl domainACL, target string) (*DomainWorkloadGrant, error) {
	grants := acl.Principals[target]
	if len(grants) == 0 {
		return nil, nil
	}
	read, write := grants[domainStoreReadOperation], grants[nativeStoreCommand]
	if len(grants) != 2 || read.WorkloadGrant == nil || write.WorkloadGrant == nil || !domainEqual(read.WorkloadGrant, write.WorkloadGrant) || read.TargetGrantRevision != read.WorkloadGrant.GrantRevision || write.TargetGrantRevision != read.TargetGrantRevision {
		return nil, fmt.Errorf("independent/legacy workload target cannot be adopted")
	}
	return read.WorkloadGrant, nil
}

func (w *enrollmentACLWrites) applyBoundWorkloadChange(acl *domainACL, record DomainRecord, kind string) (bool, error) {
	r := w.entry.enrollment.actor.Request
	target := *r.TargetPrincipalID
	prior, err := boundWorkloadListGrant(*acl, target)
	if err != nil {
		return false, err
	}
	policy := &domainOwnerPolicy{key: w.d.config.ACLMetadataKey}
	root, err := policy.acl(w.root)
	if err != nil {
		return false, err
	}
	rootPrior, err := boundWorkloadListGrant(root, target)
	if err != nil || prior != nil && !domainEqual(prior, rootPrior) {
		return false, fmt.Errorf("workload closure has an independent grant")
	}
	if r.Operation == EnrollmentWorkloadRevoke {
		if rootPrior == nil || !domainEqual(rootPrior, r.WorkloadGrant) {
			return false, fmt.Errorf("exact installed workload grant required for revoke")
		}
		return revokeBoundWorkloadList(acl, target, *r.WorkloadGrant, kind == "root")
	}
	if rootPrior != nil && rootPrior.GrantRevision == r.WorkloadGrant.GrantRevision && !domainEqual(rootPrior, r.WorkloadGrant) {
		return false, fmt.Errorf("workload grant revision cannot change immutable tuple/expiry")
	}
	return w.grantBoundWorkloadList(acl, record, kind, rootPrior)
}

func (w *enrollmentACLWrites) grantBoundWorkloadList(acl *domainACL, record DomainRecord, kind string, prior *DomainWorkloadGrant) (bool, error) {
	r := w.entry.enrollment.actor.Request
	target := *r.TargetPrincipalID
	purpose, err := workloadPurposeForGrant(w.d.config.WorkloadPolicy, *r.WorkloadGrant, true)
	if err != nil {
		return false, err
	}
	family, _ := record.Metadata[w.entry.owned.Layout.Fields["pngFamily"]].(string)
	rule, allowed := purpose.Families[family]
	if kind != "root" && (!allowed || rule.Kind != kind) {
		_, present := acl.Principals[target]
		delete(acl.Principals, target)
		return present, nil
	}
	grants, err := boundEnrollmentWorkloadGrants(w.d, w.entry, kind)
	if err != nil {
		return false, err
	}
	acl.ContractRevision = domainCoownerACLRevision
	acl.Principals[target] = grants
	if kind != "root" {
		return true, nil
	}
	return true, w.grantBoundWorkloadTemplates(acl, purpose, prior)
}

func (w *enrollmentACLWrites) grantBoundWorkloadTemplates(acl *domainACL, purpose DomainWorkloadPurpose, prior *DomainWorkloadGrant) error {
	for _, kind := range domainWithout(workloadPurposeKinds(purpose), "root") {
		if _, present := acl.CreateACLs[kind]; !present {
			return fmt.Errorf("workload owner template absent")
		}
	}
	for kind, template := range acl.CreateACLs {
		if err := w.grantBoundWorkloadTemplate(&template, kind, purpose, prior); err != nil {
			return err
		}
		acl.CreateACLs[kind] = template
	}
	return nil
}

func (w *enrollmentACLWrites) grantBoundWorkloadTemplate(template *domainACL, kind string, purpose DomainWorkloadPurpose, prior *DomainWorkloadGrant) error {
	target := *w.entry.enrollment.actor.Request.TargetPrincipalID
	actual, err := boundWorkloadListGrant(*template, target)
	if err != nil || actual != nil && !domainEqual(actual, prior) {
		return fmt.Errorf("workload template has independent grant")
	}
	if !domainContains(workloadPurposeKinds(purpose), kind) {
		delete(template.Principals, target)
		return nil
	}
	if template.Principals == nil {
		return fmt.Errorf("workload owner template principals absent")
	}
	grants, err := boundEnrollmentWorkloadGrants(w.d, w.entry, kind)
	if err != nil {
		return err
	}
	template.ContractRevision = domainCoownerACLRevision
	template.Principals[target] = grants
	return nil
}

func revokeBoundWorkloadList(acl *domainACL, target string, g DomainWorkloadGrant, root bool) (bool, error) {
	prior, err := boundWorkloadListGrant(*acl, target)
	if err != nil || prior != nil && !domainEqual(*prior, g) {
		return false, fmt.Errorf("workload revoke cannot touch another grant")
	}
	delete(acl.Principals, target)
	changed := prior != nil || root
	for name, template := range acl.CreateACLs {
		removed, err := revokeBoundWorkloadList(&template, target, g, false)
		if err != nil {
			return false, err
		}
		changed = changed || removed
		acl.CreateACLs[name] = template
	}
	return changed, nil
}

func (s *Server) validateBoundWorkloadPinsLocked(d *domainEngine, entry *domainEntry) error {
	root, nodes, err := s.enrollmentPinRecordsLocked(entry)
	if err != nil {
		return err
	}
	reader := newDomainACLReader(d.config.ACLMetadataKey, entry.owned, root)
	for _, record := range nodes {
		if enrollmentSemanticKind(entry.owned.Layout, record.Kind) == "" {
			continue
		}
		acl, err := reader.acl(record)
		if err != nil {
			return err
		}
		if _, reference, _ := domainACLReferenceOf(record.Metadata[d.config.ACLMetadataKey]); reference {
			record.ID = ""
		}
		if err = boundWorkloadPins(d, entry, acl, record, enrollmentSemanticKind(entry.owned.Layout, record.Kind)); err != nil {
			return err
		}
	}
	return nil
}

func boundWorkloadPins(d *domainEngine, entry *domainEntry, acl domainACL, record DomainRecord, kind string) error {
	r := entry.enrollment.actor.Request
	actual, err := boundWorkloadListGrant(acl, *r.TargetPrincipalID)
	if err != nil {
		return err
	}
	expected := false
	if r.Operation == EnrollmentWorkloadGrant {
		purpose, err := workloadPurposeForGrant(d.config.WorkloadPolicy, *r.WorkloadGrant, true)
		if err != nil {
			return err
		}
		family, _ := record.Metadata[entry.owned.Layout.Fields["pngFamily"]].(string)
		rule, present := purpose.Families[family]
		expected = kind == "root" || present && rule.Kind == kind || record.ID == "" && domainContains(workloadPurposeKinds(purpose), kind)
	}
	if expected {
		grants, err := boundEnrollmentWorkloadGrants(d, entry, kind)
		if err != nil || actual == nil || !domainEqual(acl.Principals[*r.TargetPrincipalID], grants) {
			return fmt.Errorf("current native workload grant replaced/removed")
		}
	} else if actual != nil {
		return fmt.Errorf("unexpected installed workload grant remains/reappeared")
	}
	for name, template := range acl.CreateACLs {
		if err := boundWorkloadPins(d, entry, template, DomainRecord{}, name); err != nil {
			return err
		}
	}
	return nil
}

func authorizeBoundWorkloadDelegation(d *domainEngine, entry *domainEntry, acl domainACL) error {
	actor := entry.enrollment.actor
	if !boundWorkloadEnrollment(actor.Request) || actor.Request.Operation == EnrollmentWorkloadRevoke {
		return nil
	}
	purpose, err := workloadPurposeForGrant(d.config.WorkloadPolicy, *actor.Request.WorkloadGrant, true)
	if err != nil {
		return err
	}
	for _, kind := range workloadPurposeKinds(purpose) {
		list := acl
		if kind != "root" {
			list = acl.CreateACLs[kind]
		}
		if err := authorizeBoundWorkloadKind(d, entry, list, kind); err != nil {
			return err
		}
	}
	return nil
}

func authorizeBoundWorkloadKind(d *domainEngine, entry *domainEntry, acl domainACL, kind string) error {
	actor := entry.enrollment.actor
	person := DomainVerified{Kind: "human", PrincipalID: actor.PrincipalID, GrantRevision: actor.GrantRevision, OwnerAuthorized: actor.OwnerAuthorized}
	required, err := boundEnrollmentWorkloadGrants(d, entry, kind)
	if err != nil {
		return err
	}
	for operation, grant := range required {
		access := DomainAccess{Operation: operation, Kind: kind, Fields: grant.Fields}
		if err := workloadDelegationDecision(person, acl, access, grant.CreateKinds); err != nil {
			return err
		}
	}
	return nil
}

func workloadDelegationDecision(actor DomainVerified, acl domainACL, access DomainAccess, kinds []string) error {
	grant, present := acl.Principals[actor.PrincipalID][access.Operation]
	if authorizeDomainGrant(actor, grant, present, access) == nil && enrollmentGrantSubset(kinds, grant.CreateKinds) {
		return nil
	}
	contribution := acl.Coowners[actor.PrincipalID]
	if coownerGrantAllows(actor, contribution, access) && enrollmentGrantSubset(kinds, contribution.Grants[access.Operation].CreateKinds) {
		return nil
	}
	return fmt.Errorf("workload delegation requires one complete currently held native grant")
}

func workloadHasBoundGrant(acl domainACL, target string) bool {
	for _, grant := range acl.Principals[target] {
		if grant.WorkloadGrant != nil {
			return true
		}
	}
	for _, template := range acl.CreateACLs {
		if workloadHasBoundGrant(template, target) {
			return true
		}
	}
	return false
}

func (s *Server) authorizeBoundWorkloadEnrollmentReplay(d *domainEngine, entry *domainEntry, access stagedAccess) error {
	if access.ReplayWorkload && boundWorkloadEnrollment(entry.enrollment.actor.Request) {
		return s.validateBoundWorkloadPinsLocked(d, entry)
	}
	return nil
}
