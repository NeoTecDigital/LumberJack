// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// The code that shipped before references, frozen verbatim as the differential's oracle: a record
// held a private copy of its template, and a member read change rewrote every record and template.
// Do not "fix" it to match the current code; the difference is what the tests measure.

func legacyCreateACL(p *domainOwnerPolicy, actor DomainVerified, operation, kind string, root DomainRecord) (interface{}, error) {
	acl, err := p.acl(root)
	if err != nil {
		return nil, err
	}
	grant, present := acl.Principals[actor.PrincipalID][operation]
	if !present || !domainContains(grant.CreateKinds, kind) {
		return nil, fmt.Errorf("owner did not delegate this creation")
	}
	template, present := acl.CreateACLs[kind]
	if !present || template.ContractRevision != "lj.domain.acl/1" || template.Principals == nil {
		return nil, fmt.Errorf("explicit owner new-record ACL template absent")
	}
	raw, err := CanonicalDomainJSON(template)
	if err != nil {
		return nil, err
	}
	var value interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	err = decoder.Decode(&value)
	return value, err
}

func legacyEnrollmentACLWrite(d *domainEngine, entry *domainEntry, record DomainRecord) (*stagedWrite, error) {
	kind := enrollmentSemanticKind(entry.owned.Layout, record.Kind)
	if kind == "" {
		return nil, nil
	}
	policy := &domainOwnerPolicy{key: d.config.ACLMetadataKey}
	acl, err := policy.acl(record)
	if err != nil {
		return nil, err
	}
	actor := entry.enrollment.actor
	target := *actor.Request.TargetPrincipalID
	if _, owner := acl.Principals[target][EnrollmentProvision]; owner {
		return nil, fmt.Errorf("owner ACL cannot be changed by member read control")
	}
	if actor.Request.Operation == EnrollmentReadGrant {
		fields := entry.owned.Layout.Profiles["read"][kind]
		if len(fields) == 0 {
			return nil, fmt.Errorf("known graph current read profile absent")
		}
		if acl.Principals[target] == nil {
			acl.Principals[target] = map[string]domainGrant{}
		}
		acl.Principals[target]["read"] = domainGrant{Fields: append([]string(nil), fields...), Reference: true, TargetGrantRevision: *actor.PrincipalReference.TargetGrantRevision}
		legacyGrantPNGRead(entry, &acl, kind, target)
	} else {
		delete(acl.Principals[target], "read")
		delete(acl.Principals[target], "png.store.read")
		if len(acl.Principals[target]) == 0 {
			delete(acl.Principals, target)
		}
	}
	if kind == "root" {
		legacyUpdateTemplates(entry, &acl, target)
	}
	value, err := enrollmentACLValue(acl)
	if err != nil {
		return nil, err
	}
	return &stagedWrite{NodeID: record.ID, Key: d.config.ACLMetadataKey, Value: value}, nil
}

func legacyGrantPNGRead(entry *domainEntry, acl *domainACL, kind, target string) {
	fields := entry.owned.Layout.Profiles["png.store.read"][kind]
	if len(fields) == 0 {
		return
	}
	revision := *entry.enrollment.actor.PrincipalReference.TargetGrantRevision
	acl.Principals[target]["png.store.read"] = domainGrant{Fields: append([]string(nil), fields...), Reference: domainContains(fields, "reference"), TargetGrantRevision: revision}
}

func legacyUpdateTemplates(entry *domainEntry, acl *domainACL, target string) {
	for kind, template := range acl.CreateACLs {
		if len(entry.owned.Layout.Profiles["read"][kind]) == 0 {
			continue
		}
		legacyUpdateTemplate(entry, &template, kind, target)
		acl.CreateACLs[kind] = template
	}
}

func legacyUpdateTemplate(entry *domainEntry, template *domainACL, kind, target string) {
	if entry.enrollment.actor.Request.Operation == EnrollmentReadRevoke {
		delete(template.Principals[target], "read")
		delete(template.Principals[target], "png.store.read")
		if len(template.Principals[target]) == 0 {
			delete(template.Principals, target)
		}
		return
	}
	if template.Principals[target] == nil {
		template.Principals[target] = map[string]domainGrant{}
	}
	fields := entry.owned.Layout.Profiles["read"][kind]
	revision := *entry.enrollment.actor.PrincipalReference.TargetGrantRevision
	template.Principals[target]["read"] = domainGrant{Fields: append([]string(nil), fields...), Reference: domainContains(fields, "reference"), TargetGrantRevision: revision}
	legacyGrantPNGRead(entry, template, kind, target)
}

// The two decisions the workload change touched, as they were before it, frozen the same way.
func legacyAuthorizeLocked(p *domainOwnerPolicy, actor DomainVerified, access DomainAccess, record DomainRecord) error {
	if p.sessionFenced != nil && p.sessionFenced(actor) {
		return fmt.Errorf("current actor session fenced")
	}
	if actor.Kind != "human" && (actor.Kind != "integration_actor" || actor.IntegrationActor == nil) || actor.ExpiresAt <= domainNow() {
		return fmt.Errorf("current human authority expired")
	}
	acl, err := p.acl(record)
	if err != nil {
		return err
	}
	grant, present := acl.Principals[actor.PrincipalID][access.Operation]
	if !present || len(access.Fields) == 0 || grant.TargetGrantRevision != "" && grant.TargetGrantRevision != actor.GrantRevision {
		return fmt.Errorf("current native action/fields denied")
	}
	for _, field := range access.Fields {
		if !domainContains(grant.Fields, field) {
			return fmt.Errorf("current native field denied: %s", field)
		}
	}
	if access.Create && !domainContains(grant.CreateKinds, access.Kind) {
		return fmt.Errorf("current native create denied")
	}
	if access.Reference && !grant.Reference {
		return fmt.Errorf("current native reference denied")
	}
	return nil
}

func legacyValidDomainActorKind(d *domainEngine, actor DomainVerified) bool {
	if actor.Kind == "human" {
		return actor.Issuer == d.config.Trust.Issuer && actor.IntegrationActor == nil
	}
	if actor.Kind != "integration_actor" || actor.IntegrationActor == nil || d.config.IntegrationIssuer == "" {
		return false
	}
	if actor.Issuer != d.config.IntegrationIssuer || !strings.HasPrefix(actor.SessionID, "channel-message:") {
		return false
	}
	profile := actor.IntegrationActor
	values := []string{profile.IntegrationID, profile.ConnectorID, profile.MessageID, profile.MessageHash, profile.CredentialRevision, profile.PolicyRevision, profile.RosterRevision, profile.SenderPhone}
	for _, value := range values {
		if value == "" {
			return false
		}
	}
	for _, char := range profile.SenderPhone {
		if char < '0' || char > '9' {
			return false
		}
	}
	if !domainValidHash(profile.MessageHash) || actor.AuthorityResourceRevision != profile.PolicyRevision {
		return false
	}
	if profile.EffectiveAssociateID == nil {
		return actor.PrincipalID == "office-intake:"+profile.IntegrationID
	}
	return *profile.EffectiveAssociateID != "" && actor.PrincipalID == "associate:"+*profile.EffectiveAssociateID
}
