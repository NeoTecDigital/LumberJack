// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

// enrollmentACLWrites computes one member read change for every known record of a scope. A record
// holding a full list is rewritten as always. A record following its kind's template needs no write
// when the template's own change gives the same decisions, and otherwise takes the full list the
// change produces, which leaves it correct on its own from then on.
type enrollmentACLWrites struct {
	d         *domainEngine
	entry     *domainEntry
	root      DomainRecord
	following map[string]*enrollmentFollowing
	followers map[string]int // Counted on the walk the change already makes; nil until there is one.
}

// value is nil when records of the kind keep following the template.
type enrollmentFollowing struct {
	value interface{}
	err   error
}

func newEnrollmentACLWrites(d *domainEngine, entry *domainEntry, root DomainRecord) *enrollmentACLWrites {
	return &enrollmentACLWrites{d: d, entry: entry, root: root, following: map[string]*enrollmentFollowing{}}
}

func (w *enrollmentACLWrites) of(record DomainRecord) (*stagedWrite, error) {
	kind := enrollmentSemanticKind(w.entry.owned.Layout, record.Kind)
	if kind == "" {
		return nil, nil // Unknown source bags/resources are never broadened.
	}
	if isEnrollmentWorkloadOperation(w.entry.enrollment.actor.Request.Operation) {
		return w.workloadWrite(record, kind)
	}
	key := w.d.config.ACLMetadataKey
	_, reference, err := domainRecordACLValue(key, w.entry.owned, w.root, record)
	if err != nil {
		return nil, err
	}
	if reference {
		return w.followerWrite(record, kind)
	}
	after, err := w.changedList(record, kind)
	if err != nil {
		return nil, err
	}
	return &stagedWrite{NodeID: record.ID, Key: key, Value: after}, nil
}

func (w *enrollmentACLWrites) followerWrite(record DomainRecord, kind string) (*stagedWrite, error) {
	after, err := w.followingValue(kind)
	if err != nil {
		return nil, err
	}
	if after != nil {
		return &stagedWrite{NodeID: record.ID, Key: w.d.config.ACLMetadataKey, Value: after}, nil
	}
	w.countFollower(kind)
	return nil, nil
}

func (w *enrollmentACLWrites) countFollower(kind string) {
	if w.followers == nil {
		w.followers = map[string]int{}
	}
	w.followers[kind]++
}

func (w *enrollmentACLWrites) changedList(record DomainRecord, kind string) (interface{}, error) {
	policy := &domainOwnerPolicy{key: w.d.config.ACLMetadataKey}
	acl, err := policy.acl(record)
	if err != nil {
		return nil, err
	}
	if err = applyEnrollmentRecordChange(w.entry, &acl, kind); err != nil {
		return nil, err
	}
	if kind == "root" {
		updateEnrollmentReadTemplates(w.entry, &acl, *w.entry.enrollment.actor.Request.TargetPrincipalID)
	}
	return enrollmentACLValue(acl)
}

// Every record following a kind's template starts from the same list, so one answer serves them all.
func (w *enrollmentACLWrites) followingValue(kind string) (interface{}, error) {
	if known := w.following[kind]; known != nil {
		return known.value, known.err
	}
	value, err := w.followingChange(kind)
	w.following[kind] = &enrollmentFollowing{value: value, err: err}
	return value, err
}

func (w *enrollmentACLWrites) followingChange(kind string) (interface{}, error) {
	key := w.d.config.ACLMetadataKey
	template, err := domainACLTemplateValue(key, w.root, kind)
	if err != nil {
		return nil, err
	}
	list := DomainRecord{Metadata: map[string]interface{}{key: template}}
	policy := &domainOwnerPolicy{key: key}
	record, err := policy.acl(list)
	if err != nil {
		return nil, err
	}
	if err = applyEnrollmentRecordChange(w.entry, &record, kind); err != nil {
		return nil, err
	}
	changed, err := policy.acl(list)
	if err != nil {
		return nil, err
	}
	updateEnrollmentTemplateTarget(w.entry, &changed, kind, *w.entry.enrollment.actor.Request.TargetPrincipalID)
	if domainACLDecisionsEqual(record, changed) {
		return nil, nil
	}
	return enrollmentACLValue(record)
}

func applyEnrollmentRecordChange(entry *domainEntry, acl *domainACL, kind string) error {
	actor := entry.enrollment.actor
	target := *actor.Request.TargetPrincipalID
	if _, owner := acl.Principals[target][EnrollmentProvision]; owner {
		return fmt.Errorf("owner ACL cannot be changed by member read control")
	}
	if actor.Request.Operation != EnrollmentReadGrant {
		revokeEnrollmentRead(acl, target)
		return nil
	}
	fields := entry.owned.Layout.Profiles["read"][kind]
	if len(fields) == 0 {
		return fmt.Errorf("known graph current read profile absent")
	}
	if acl.Principals[target] == nil {
		acl.Principals[target] = map[string]domainGrant{}
	}
	acl.Principals[target]["read"] = domainGrant{Fields: append([]string(nil), fields...), Reference: true, TargetGrantRevision: *actor.PrincipalReference.TargetGrantRevision}
	grantPNGEnrollmentRead(entry, acl, kind, target)
	return nil
}

func revokeEnrollmentRead(acl *domainACL, target string) {
	delete(acl.Principals[target], "read")
	delete(acl.Principals[target], "png.store.read")
	if len(acl.Principals[target]) == 0 {
		delete(acl.Principals, target)
	}
}
