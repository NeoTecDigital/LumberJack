// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"sort"
)

func authorizeCoownerControl(actor EnrollmentVerified, acl domainACL, founder string) error {
	c := actor.Request.CoownerChange
	if c != nil && (c.FounderPrincipalID != founder || *actor.Request.TargetPrincipalID == founder) {
		return fmt.Errorf("original founder identity mismatch")
	}
	operation := enrollmentControlOperation(actor.Request.Operation)
	if c != nil && actor.PrincipalID == founder {
		grant := acl.Principals[founder][EnrollmentProvision]
		if grant.TargetGrantRevision == "" && domainEqual(grant.Fields, []string{"acl"}) && !grant.Reference && len(grant.CreateKinds) == 0 {
			return nil
		}
	}
	contribution := acl.Coowners[actor.PrincipalID]
	if isEnrollmentWorkloadOperation(actor.Request.Operation) {
		grant := contribution.Grants[nativeStoreCommand]
		if grant.TargetGrantRevision != actor.GrantRevision || !domainContains(grant.CreateKinds, domainWorkloadCreateKind) {
			return fmt.Errorf("co-owner cannot delegate a workload write it does not hold")
		}
	}
	person := DomainVerified{Kind: actor.Kind, PrincipalID: actor.PrincipalID, GrantRevision: actor.GrantRevision}
	access := DomainAccess{Operation: operation, Fields: []string{"acl"}}
	if actor.OwnerAuthorized && coownerGrantAllows(person, acl.Coowners[actor.PrincipalID], access) {
		return nil
	}
	return fmt.Errorf("current own native co-owner control denied")
}

func buildCoownerDelta(d *domainEngine, entry *domainEntry, view stagedView) (stagedDelta, error) {
	root := view.Records[entry.owned.Binding.RootID]
	policy := &domainOwnerPolicy{key: d.config.ACLMetadataKey}
	acl, err := policy.acl(root)
	if err != nil {
		return stagedDelta{}, err
	}
	if err = validateCoownerGeneration(entry.enrollment.actor.Request, acl); err != nil {
		return stagedDelta{}, err
	}
	w := newEnrollmentACLWrites(d, entry, root)
	delta := stagedDelta{}
	effects := []coownerACLEffect{}
	ids := make([]string, 0, len(view.Records))
	for id := range view.Records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		write, effect, err := w.coownerWrite(view.Records[id], acl.Coowners[*entry.enrollment.actor.Request.TargetPrincipalID])
		if err != nil {
			return stagedDelta{}, err
		}
		if write != nil {
			delta.Writes = append(delta.Writes, *write)
			effects = append(effects, effect)
		}
	}
	delta.Followers = w.followers
	entry.enrollment.effectDigest = coownerEffectDigest(effects, delta.Followers)
	if err := validateEnrollmentResponseBound(d, entry, view.Revision); err != nil {
		return stagedDelta{}, err
	}
	record, err := coownerRecord(entry.enrollment.actor, entry.enrollment.effectDigest)
	if err != nil {
		return stagedDelta{}, err
	}
	record.ACLEffectDigest = entry.enrollment.effectDigest
	delta.EnrollmentRecord, err = CanonicalDomainJSON(record)
	return delta, err
}

func validateCoownerGeneration(r EnrollmentRequest, root domainACL) error {
	current, exists := root.Coowners[*r.TargetPrincipalID]
	c := r.CoownerChange
	if c.ExpectedCoownerGrantRevision == nil {
		if exists {
			return fmt.Errorf("co-owner generation absence CAS failed")
		}
	} else if !exists || current.GrantRevision != *c.ExpectedCoownerGrantRevision || current.ProfileRef != r.ProfileRef {
		return fmt.Errorf("co-owner generation CAS failed")
	}
	if r.Operation == EnrollmentCoownerGrant && exists && current.State != "revoked" {
		return fmt.Errorf("installed co-owner cannot be replaced")
	}
	if r.Operation == EnrollmentCoownerRevoke && (!exists || current.State != "installed") {
		return fmt.Errorf("exact installed co-owner required")
	}
	return nil
}

func (w *enrollmentACLWrites) coownerWrite(record DomainRecord, prior domainCoownerContribution) (*stagedWrite, coownerACLEffect, error) {
	kind := enrollmentSemanticKind(w.entry.owned.Layout, record.Kind)
	if kind == "" {
		return nil, coownerACLEffect{}, nil
	}
	raw, reference, err := domainRecordACLValue(w.d.config.ACLMetadataKey, w.entry.owned, w.root, record)
	if err != nil {
		return nil, coownerACLEffect{}, err
	}
	if reference && w.following[kind] != nil {
		w.countFollower(kind)
		return nil, coownerACLEffect{}, nil
	}
	policy := &domainOwnerPolicy{key: w.d.config.ACLMetadataKey}
	acl, err := policy.acl(DomainRecord{Metadata: map[string]interface{}{policy.key: raw}})
	if err != nil {
		return nil, coownerACLEffect{}, err
	}
	before := coownerContributionValue(acl, *w.entry.enrollment.actor.Request.TargetPrincipalID)
	if err = w.changeCoownerACL(&acl, kind, prior); err != nil {
		return nil, coownerACLEffect{}, err
	}
	if reference {
		w.following[kind] = &enrollmentFollowing{}
		w.countFollower(kind) // The same bounded change is applied to that exact root/kind template.
		return nil, coownerACLEffect{}, nil
	}
	after, err := enrollmentACLValue(acl)
	effect := coownerACLEffect{record.ID, before, coownerContributionValue(acl, *w.entry.enrollment.actor.Request.TargetPrincipalID)}
	return &stagedWrite{NodeID: record.ID, Key: policy.key, Value: after}, effect, err
}

func (w *enrollmentACLWrites) changeCoownerACL(acl *domainACL, kind string, prior domainCoownerContribution) error {
	r := w.entry.enrollment.actor.Request
	if err := coownerPriorIdentity(*acl, r, kind, prior); err != nil {
		return err
	}
	if err := changeCoownerContribution(acl, r, kind, w.d.config.ProvisioningProfile); err != nil {
		return err
	}
	if kind != "root" {
		return nil
	}
	for name, template := range acl.CreateACLs {
		if w.entry.owned.Layout.Kinds[name] == "" {
			continue
		}
		if err := coownerPriorIdentity(template, r, name, prior); err != nil {
			return err
		}
		if err := changeCoownerContribution(&template, r, name, w.d.config.ProvisioningProfile); err != nil {
			return err
		}
		acl.CreateACLs[name] = template
	}
	return nil
}

func coownerPriorIdentity(acl domainACL, r EnrollmentRequest, kind string, prior domainCoownerContribution) error {
	current, exists := acl.Coowners[*r.TargetPrincipalID]
	want := prior.State != "" && (kind == "root" || prior.State == "installed")
	if exists != want || exists && !coownerSameGeneration(current, prior) {
		return fmt.Errorf("co-owner closure contains an independent/replaced contribution")
	}
	return nil
}

func coownerSameGeneration(left, right domainCoownerContribution) bool {
	return left.State == right.State && left.GrantRevision == right.GrantRevision && left.GrantCommandID == right.GrantCommandID && left.GrantFingerprint == right.GrantFingerprint && left.ProfileRef == right.ProfileRef
}

func changeCoownerContribution(acl *domainACL, r EnrollmentRequest, kind string, profile *DomainProvisioningProfile) error {
	target := *r.TargetPrincipalID
	if acl.Coowners == nil {
		acl.Coowners = map[string]domainCoownerContribution{}
	}
	acl.ContractRevision = domainCoownerACLRevision
	if r.Operation == EnrollmentCoownerRevoke {
		return revokeCoownerContribution(acl, r, kind)
	}
	if old, exists := acl.Coowners[target]; exists && old.State != "revoked" {
		return fmt.Errorf("independent installed generation cannot be overwritten")
	}
	grants := coownerBoundedGrants(profile.OwnerGrants[kind], acl.Principals[r.CoownerChange.FounderPrincipalID], *r.CoownerChange.OwnerGrantRevision)
	if kind == "root" {
		coownerControlGrants(grants, *r.CoownerChange.OwnerGrantRevision)
	}
	acl.Coowners[target] = domainCoownerContribution{"installed", *r.CoownerChange.OwnerGrantRevision, r.CommandID, coownerRequestFingerprint(r), r.ProfileRef, grants}
	return nil
}

func revokeCoownerContribution(acl *domainACL, r EnrollmentRequest, kind string) error {
	target := *r.TargetPrincipalID
	current, present := acl.Coowners[target]
	if !present || current.State != "installed" || current.GrantRevision != *r.CoownerChange.ExpectedCoownerGrantRevision || current.ProfileRef != r.ProfileRef {
		return fmt.Errorf("co-owner revoke contribution missing/replaced")
	}
	delete(acl.Coowners, target)
	if kind == "root" {
		current.State, current.Grants = "revoked", map[string]domainGrant{}
		acl.Coowners[target] = current
	}
	return nil
}

func coownerBoundedGrants(profile, exceptional map[string]domainGrant, revision string) map[string]domainGrant {
	grants := map[string]domainGrant{}
	for operation, bound := range profile {
		actual, present := exceptional[operation]
		if !present {
			continue
		}
		fields := coownerIntersection(bound.Fields, actual.Fields)
		if len(fields) == 0 {
			continue
		}
		grants[operation] = domainGrant{Fields: fields, CreateKinds: coownerIntersection(bound.CreateKinds, actual.CreateKinds), Reference: bound.Reference && actual.Reference, TargetGrantRevision: revision}
	}
	return grants
}

func coownerIntersection(bound, actual []string) []string {
	result := []string{}
	for _, field := range bound {
		if domainContains(actual, field) {
			result = append(result, field)
		}
	}
	return result
}

func coownerControlGrants(grants map[string]domainGrant, revision string) {
	if !domainEqual(grants[EnrollmentProvision].Fields, []string{"acl"}) {
		return
	}
	for _, operation := range []string{EnrollmentCoownerGrant, EnrollmentCoownerRevoke} {
		grants[operation] = domainGrant{Fields: []string{"acl"}, TargetGrantRevision: revision}
	}
}

func coownerRequestFingerprint(request EnrollmentRequest) string {
	raw, err := CanonicalDomainJSON(request)
	if err != nil {
		return ""
	}
	return stagedHash(raw)
}

func (s *Server) validateCoownerPinsLocked(d *domainEngine, entry *domainEntry) error {
	root, records, err := s.enrollmentPinRecordsLocked(entry)
	if err != nil {
		return err
	}
	reader := newDomainACLReader(d.config.ACLMetadataKey, entry.owned, root)
	for _, record := range records {
		if enrollmentSemanticKind(entry.owned.Layout, record.Kind) == "" {
			continue
		}
		acl, err := reader.acl(record)
		if err != nil {
			return err
		}
		if err = coownerPinnedACL(entry.enrollment.actor.Request, acl, enrollmentSemanticKind(entry.owned.Layout, record.Kind), d.config.ProvisioningProfile); err != nil {
			return err
		}
	}
	return nil
}

func coownerPinnedACL(r EnrollmentRequest, acl domainACL, kind string, profile *DomainProvisioningProfile) error {
	root := kind == "root"
	c, present := acl.Coowners[*r.TargetPrincipalID]
	if r.Operation == EnrollmentCoownerGrant {
		if !present || c.State != "installed" || c.GrantRevision != *r.CoownerChange.OwnerGrantRevision || c.GrantCommandID != r.CommandID || c.GrantFingerprint != coownerRequestFingerprint(r) || c.ProfileRef != r.ProfileRef {
			return fmt.Errorf("installed co-owner pin removed/replaced")
		}
		expected := coownerBoundedGrants(profile.OwnerGrants[kind], acl.Principals[r.CoownerChange.FounderPrincipalID], c.GrantRevision)
		if root {
			coownerControlGrants(expected, c.GrantRevision)
		}
		if !domainEqual(c.Grants, expected) {
			return fmt.Errorf("co-owner bounded contribution changed")
		}
	} else if root {
		if !present || c.State != "revoked" || c.GrantRevision != *r.CoownerChange.ExpectedCoownerGrantRevision {
			return fmt.Errorf("co-owner revocation tombstone replaced")
		}
	} else if present {
		return fmt.Errorf("revoked co-owner contribution remains")
	}
	for name, template := range acl.CreateACLs {
		if profile.Layout.Kinds[name] == "" {
			continue
		}
		if err := coownerPinnedACL(r, template, name, profile); err != nil {
			return err
		}
	}
	return nil
}
