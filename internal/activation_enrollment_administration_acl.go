// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"

	"github.com/NeoTecDigital/LumberJack/core"
)

func enrollmentOwnerPrincipal(actor EnrollmentVerified) string {
	if actor.Request.Administration != nil {
		return actor.Request.Administration.OwnerPrincipalID
	}
	return actor.PrincipalID
}

func enrollmentAdministrationACL(p *DomainProvisioningProfile, actor EnrollmentVerified) domainACL {
	owner := enrollmentOwnerPrincipal(actor)
	acl := enrollmentACL(p, owner, "root")
	if actor.Request.Administration == nil || owner == actor.PrincipalID {
		return acl
	}
	enrollmentAddAdministrator(&acl, actor, "root")
	for kind, template := range acl.CreateACLs {
		enrollmentAddAdministrator(&template, actor, kind)
		acl.CreateACLs[kind] = template
	}
	return acl
}

func enrollmentAddAdministrator(acl *domainACL, actor EnrollmentVerified, kind string) {
	if grants := actor.Request.Administration.Grants[kind]; len(grants) != 0 {
		acl.Principals[actor.PrincipalID] = grants
	}
}

func (s *Server) authorizeEnrollmentAdministrationLocked(d *domainEngine, entry *domainEntry, account, root *core.Node, acl domainACL) error {
	actor := entry.enrollment.actor
	p, err := d.enrollmentProfile(actor.Request)
	if err != nil || !enrollmentActorAuthorized(actor) || root.CreatedBy != enrollmentOwnerPrincipal(actor) || root.Name != actor.Request.Administration.Name {
		return fmt.Errorf("current explicit administrator owner/profile/name denied")
	}
	if account == nil || account.CreatedBy != root.CreatedBy || account.Name != root.Name {
		return fmt.Errorf("original native account owner/name changed")
	}
	if !enrollmentAdministrationPins(acl, enrollmentAdministrationACL(p, actor), actor) {
		return fmt.Errorf("current administrator root/template authority revoked/replaced")
	}
	nodes, err := stagedClosure(root, entry.owned.Bounds)
	if err != nil {
		return err
	}
	reader := newDomainACLReader(d.config.ACLMetadataKey, entry.owned, DomainRecord{ID: root.ID, Kind: root.Kind, Metadata: root.Metadata})
	for _, node := range nodes {
		if err = enrollmentAdministrationNodePins(reader, p, actor, node); err != nil {
			return err
		}
	}
	return nil
}

func enrollmentAdministrationNodePins(reader *domainACLReader, p *DomainProvisioningProfile, actor EnrollmentVerified, node *core.Node) error {
	kind := enrollmentSemanticKind(p.Layout, node.Kind)
	if kind == "" {
		return nil // Unknown bags/resources are not delegated by enrollment.
	}
	acl, err := reader.acl(DomainRecord{ID: node.ID, Kind: node.Kind, Metadata: node.Metadata})
	if err != nil {
		return err
	}
	owner := enrollmentOwnerPrincipal(actor)
	if !domainEqual(acl.Principals[owner], p.OwnerGrants[kind]) {
		return fmt.Errorf("original native owner grants revoked/replaced")
	}
	if actor.PrincipalID != owner && !domainEqual(acl.Principals[actor.PrincipalID], actor.Request.Administration.Grants[kind]) {
		return fmt.Errorf("explicit administrator grants revoked/replaced")
	}
	return nil
}

func enrollmentAdministrationPins(actual, expected domainACL, actor EnrollmentVerified) bool {
	owner := enrollmentOwnerPrincipal(actor)
	if !domainEqual(actual.Principals[owner], expected.Principals[owner]) || !domainEqual(actual.Principals[actor.PrincipalID], expected.Principals[actor.PrincipalID]) {
		return false
	}
	if len(actual.CreateACLs) != len(expected.CreateACLs) {
		return false
	}
	for kind, template := range expected.CreateACLs {
		if !enrollmentAdministrationPins(actual.CreateACLs[kind], template, actor) {
			return false
		}
	}
	return true
}
