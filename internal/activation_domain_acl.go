// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

type domainACL struct {
	ContractRevision string                               `json:"contractRevision"`
	Principals       map[string]map[string]domainGrant    `json:"principals"`
	CreateACLs       map[string]domainACL                 `json:"createACLs,omitempty"`
	Coowners         map[string]domainCoownerContribution `json:"coowners,omitempty"`
}
type domainGrant struct {
	TargetGrantRevision string   `json:"targetGrantRevision,omitempty"`
	Fields              []string `json:"fields"`
	CreateKinds         []string `json:"createKinds,omitempty"`
	Reference           bool     `json:"reference,omitempty"`
}
type domainOwnerPolicy struct {
	key           string
	sessionFenced func(DomainVerified) bool
	workload      *DomainWorkloadPolicy
}

func NewDomainOwnerPolicy(metadataKey string) (DomainPolicy, error) {
	if metadataKey == "" {
		return nil, fmt.Errorf("explicit owner ACL metadata key required")
	}
	return &domainOwnerPolicy{key: metadataKey}, nil
}
func (p *domainOwnerPolicy) acl(record DomainRecord) (domainACL, error) {
	raw, present := record.Metadata[p.key]
	if !present {
		return domainACL{}, fmt.Errorf("current native ACL absent")
	}
	data, err := CanonicalDomainJSON(raw)
	if err != nil {
		return domainACL{}, err
	}
	var acl domainACL
	if DecodeDomainJSON(data, &acl) != nil || !coownerACLRevision(acl.ContractRevision) || acl.Principals == nil {
		return domainACL{}, fmt.Errorf("invalid current native ACL")
	}
	if err := validateCoownerACL(acl); err != nil {
		return domainACL{}, err
	}
	return acl, nil
}
func (p *domainOwnerPolicy) AuthorizeLocked(actor DomainVerified, access DomainAccess, record DomainRecord) error {
	if p.sessionFenced != nil && p.sessionFenced(actor) {
		return fmt.Errorf("current actor session fenced")
	}
	if actor.Kind != "human" && actor.Kind != domainWorkloadKind && (actor.Kind != "integration_actor" || actor.IntegrationActor == nil) || actor.ExpiresAt <= domainNow() {
		return fmt.Errorf("current human authority expired")
	}
	if actor.Kind == domainWorkloadKind {
		if err := authorizeDomainWorkloadAccess(p.workload, actor, access); err != nil {
			return err
		}
	}
	acl, err := p.acl(record)
	if err != nil {
		return err
	}
	grant, present := acl.Principals[actor.PrincipalID][access.Operation]
	denied := authorizeDomainGrant(actor, grant, present, access)
	if denied == nil || coownerGrantAllows(actor, acl.Coowners[actor.PrincipalID], access) {
		return nil
	}
	return denied
}

// A single grant must cover every field, creation kind and reference requirement.
// If neither contribution suffices, preserve the original principal grant's denial.
func authorizeDomainGrant(actor DomainVerified, grant domainGrant, present bool, access DomainAccess) error {
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
func (p *domainOwnerPolicy) CreateACLLocked(actor DomainVerified, operation, kind string, root DomainRecord) (interface{}, error) {
	acl, err := p.acl(root)
	if err != nil {
		return nil, err
	}
	grant, present := acl.Principals[actor.PrincipalID][operation]
	if !present || grant.TargetGrantRevision != "" && grant.TargetGrantRevision != actor.GrantRevision || !domainContains(grant.CreateKinds, kind) {
		contribution := acl.Coowners[actor.PrincipalID]
		grant = contribution.Grants[operation]
		if coownerEligible(actor, contribution) && grant.TargetGrantRevision == contribution.GrantRevision && domainContains(grant.CreateKinds, kind) {
			return coownerCreateTemplate(acl, kind, root.ID)
		}
		return nil, fmt.Errorf("owner did not delegate this creation")
	}
	template, present := acl.CreateACLs[kind]
	if !present || !coownerACLRevision(template.ContractRevision) || template.Principals == nil {
		return nil, fmt.Errorf("explicit owner new-record ACL template absent")
	}
	return domainACLReferenceValue(root.ID, kind), nil
}
func domainContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
