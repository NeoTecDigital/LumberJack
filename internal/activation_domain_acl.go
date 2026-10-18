// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type domainACL struct {
	ContractRevision string                            `json:"contractRevision"`
	Principals       map[string]map[string]domainGrant `json:"principals"`
	CreateACLs       map[string]domainACL              `json:"createACLs,omitempty"`
}
type domainGrant struct {
	Fields      []string `json:"fields"`
	CreateKinds []string `json:"createKinds,omitempty"`
	Reference   bool     `json:"reference,omitempty"`
}
type domainOwnerPolicy struct{ key string }

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
	if DecodeDomainJSON(data, &acl) != nil || acl.ContractRevision != "lj.domain.acl/1" || acl.Principals == nil {
		return domainACL{}, fmt.Errorf("invalid current native ACL")
	}
	return acl, nil
}
func (p *domainOwnerPolicy) AuthorizeLocked(actor DomainVerified, access DomainAccess, record DomainRecord) error {
	if actor.Kind != "human" || actor.ExpiresAt <= domainNow() {
		return fmt.Errorf("current human authority expired")
	}
	acl, err := p.acl(record)
	if err != nil {
		return err
	}
	grant, present := acl.Principals[actor.PrincipalID][access.Operation]
	if !present || len(access.Fields) == 0 {
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
func domainContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
