// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

const EnrollmentWorkloadGrant = "manifest.scope.workload.grant"
const EnrollmentWorkloadRevoke = "manifest.scope.workload.revoke"

func isEnrollmentWorkloadOperation(operation string) bool {
	return operation == EnrollmentWorkloadGrant || operation == EnrollmentWorkloadRevoke
}

func isEnrollmentGrantOperation(operation string) bool {
	return operation == EnrollmentReadGrant || operation == EnrollmentWorkloadGrant
}

func isEnrollmentRevokeOperation(operation string) bool {
	return operation == EnrollmentReadRevoke || operation == EnrollmentWorkloadRevoke
}

// The protected profile names only the read controls, and it cannot gain a name without changing
// its digest and every account id derived from it. So the right to change a workload's access is
// the owner's existing right to change a member's: the same grant on the same root.
func enrollmentControlOperation(operation string) string {
	switch operation {
	case EnrollmentWorkloadGrant:
		return EnrollmentReadGrant
	case EnrollmentWorkloadRevoke:
		return EnrollmentReadRevoke
	}
	return operation
}

// A person is never a workload, a workload is never a control's actor, a read control never names a
// workload, and a workload control names nothing else.
func (d *domainEngine) validEnrollmentWorkloadForms(actor EnrollmentVerified) bool {
	if domainWorkloadIdentity(actor.PrincipalID, actor.SessionID) {
		return false
	}
	if a := actor.Request.Administration; a != nil && domainWorkloadIdentity(a.OwnerPrincipalID, "") {
		return false
	}
	target := actor.Request.TargetPrincipalID
	if !isEnrollmentWorkloadOperation(actor.Request.Operation) {
		return target == nil || !domainWorkloadIdentity(*target, "")
	}
	if d.config.WorkloadPolicy == nil || target == nil {
		return false
	}
	_, valid := domainWorkloadID(*target)
	return valid
}

// Provisioning has no root list to check yet. A workload control comes from someone already holding
// the store write and the record creation it hands on.
func enrollmentAdministratorMayDelegate(actor EnrollmentVerified, acl domainACL) bool {
	if !isEnrollmentWorkloadOperation(actor.Request.Operation) {
		return true
	}
	grant, present := acl.Principals[actor.PrincipalID][nativeStoreCommand]
	return present && domainContains(grant.CreateKinds, domainWorkloadCreateKind)
}

func enrollmentWorkloadGrants(d *domainEngine, entry *domainEntry, kind string) (map[string]domainGrant, error) {
	policy, layout := d.config.WorkloadPolicy, entry.owned.Layout
	if policy == nil {
		return nil, fmt.Errorf("workload policy absent")
	}
	revision := *entry.enrollment.actor.PrincipalReference.TargetGrantRevision
	grants := map[string]domainGrant{}
	for _, operation := range []string{domainStoreReadOperation, nativeStoreCommand} {
		fields, err := domainWorkloadGrantFields(policy, layout, operation, kind)
		if err != nil {
			return nil, err
		}
		grant := domainGrant{Fields: fields, TargetGrantRevision: revision}
		if kind == "root" && operation == nativeStoreCommand {
			grant.CreateKinds = []string{domainWorkloadCreateKind}
		}
		grants[operation] = grant
	}
	return grants, nil
}

// One access list change. Root and the store template always change; a record holding its own copy
// changes when it needs to; a record following the template is reached by that template's change.
func (w *enrollmentACLWrites) workloadWrite(record DomainRecord, kind string) (*stagedWrite, error) {
	key := w.d.config.ACLMetadataKey
	_, reference, err := domainRecordACLValue(key, w.entry.owned, w.root, record)
	if err != nil {
		return nil, err
	}
	if reference {
		if kind == domainWorkloadCreateKind {
			w.countFollower(kind)
		}
		return nil, nil
	}
	policy := &domainOwnerPolicy{key: key}
	acl, err := policy.acl(record)
	if err != nil {
		return nil, err
	}
	changed, err := w.applyWorkloadChange(&acl, record, kind)
	if err != nil || !changed {
		return nil, err
	}
	value, err := enrollmentACLValue(acl)
	if err != nil {
		return nil, err
	}
	return &stagedWrite{NodeID: record.ID, Key: key, Value: value}, nil
}

func (w *enrollmentACLWrites) applyWorkloadChange(acl *domainACL, record DomainRecord, kind string) (bool, error) {
	actor := w.entry.enrollment.actor
	target := *actor.Request.TargetPrincipalID
	if _, owner := acl.Principals[target][EnrollmentProvision]; owner {
		return false, fmt.Errorf("owner ACL cannot be changed by workload control")
	}
	if actor.Request.Operation == EnrollmentWorkloadRevoke {
		return w.revokeWorkload(acl, kind, target), nil
	}
	if kind == "root" {
		return true, w.grantWorkloadRoot(acl, target)
	}
	if kind != domainWorkloadCreateKind || !w.workloadRecordInFamily(record) {
		return false, nil
	}
	grants, err := enrollmentWorkloadGrants(w.d, w.entry, kind)
	if err != nil {
		return false, err
	}
	acl.Principals[target] = grants
	return true, nil
}

func (w *enrollmentACLWrites) grantWorkloadRoot(acl *domainACL, target string) error {
	rootGrants, err := enrollmentWorkloadGrants(w.d, w.entry, "root")
	if err != nil {
		return err
	}
	recordGrants, err := enrollmentWorkloadGrants(w.d, w.entry, domainWorkloadCreateKind)
	if err != nil {
		return err
	}
	template, present := acl.CreateACLs[domainWorkloadCreateKind]
	if !present || template.Principals == nil {
		return fmt.Errorf("explicit owner new-record ACL template absent")
	}
	acl.Principals[target] = rootGrants
	template.Principals[target] = recordGrants
	acl.CreateACLs[domainWorkloadCreateKind] = template
	return nil
}

// Removes the target wherever this list names it, templates included. Root is always written.
func (w *enrollmentACLWrites) revokeWorkload(acl *domainACL, kind, target string) bool {
	_, listed := acl.Principals[target]
	delete(acl.Principals, target)
	for name, template := range acl.CreateACLs {
		delete(template.Principals, target)
		acl.CreateACLs[name] = template
	}
	return listed || kind == "root"
}

func (w *enrollmentACLWrites) workloadRecordInFamily(record DomainRecord) bool {
	family, _ := record.Metadata[w.entry.owned.Layout.Fields["pngFamily"]].(string)
	_, present := w.d.config.WorkloadPolicy.Families[family]
	return present
}

// The handoff recheck: a grant replaced or removed after its command is refused here.
func (s *Server) validateEnrollmentWorkloadPinLocked(d *domainEngine, entry *domainEntry) error {
	root, nodes, err := s.enrollmentPinRecordsLocked(entry)
	if err != nil {
		return err
	}
	reader := newDomainACLReader(d.config.ACLMetadataKey, entry.owned, root)
	writes := newEnrollmentACLWrites(d, entry, root)
	kindOf := entry.owned.Layout.Kinds[domainWorkloadCreateKind]
	template, err := reader.template(domainWorkloadCreateKind)
	if err != nil || !enrollmentWorkloadPinned(entry, template) {
		return fmt.Errorf("native workload template was removed/replaced after command")
	}
	for _, record := range nodes {
		if record.ID != root.ID && (record.Kind != kindOf || !writes.workloadRecordInFamily(record)) {
			continue
		}
		acl, err := reader.acl(record)
		if err != nil {
			return err
		}
		if !enrollmentWorkloadPinned(entry, acl) {
			return fmt.Errorf("native workload grant was removed/replaced after command")
		}
	}
	return nil
}

func enrollmentWorkloadPinned(entry *domainEntry, acl domainACL) bool {
	target := entry.enrollment.actor.PrincipalReference
	for _, operation := range []string{domainStoreReadOperation, nativeStoreCommand} {
		if acl.Principals[target.PrincipalID][operation].TargetGrantRevision != *target.TargetGrantRevision {
			return false
		}
	}
	return true
}
