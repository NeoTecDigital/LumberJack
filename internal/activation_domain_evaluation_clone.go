// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

// Preserve all other DomainView fields for normal Resolve callers, but never
// give a product the private records later used for native policy evaluation.
func cloneDomainResolveView(view DomainView, bounds DomainBounds) (DomainView, error) {
	copy := view
	copy.Records = make(map[string]DomainRecord, len(view.Records))
	for id, record := range view.Records {
		cloned, err := cloneDomainEvaluationRecord(record, bounds)
		if err != nil {
			return DomainView{}, err
		}
		copy.Records[id] = cloned
	}
	return copy, nil
}

// Clone exactly one record per callback, never the entire view per target.
func cloneDomainEvaluationRecord(record DomainRecord, bounds DomainBounds) (DomainRecord, error) {
	if record.Metadata == nil {
		return record, nil
	}
	metadata, err := cloneStagedMetadata(record.Metadata, bounds)
	if err != nil {
		return DomainRecord{}, err
	}
	record.Metadata = metadata
	return record, nil
}

func (d *domainEngine) domainPolicyRecord(actor DomainVerified, record DomainRecord) (DomainRecord, error) {
	owned, present := d.scopes[actor.Scope]
	if !present {
		return DomainRecord{}, fmt.Errorf("current native policy scope absent")
	}
	return cloneDomainEvaluationRecord(record, owned.Bounds)
}

// The policy sees the full list either way: it decides exactly as it does for a stored copy.
func (d *domainEngine) domainResolvedPolicyRecord(actor DomainVerified, view DomainView, record DomainRecord) (DomainRecord, error) {
	copy, err := d.domainPolicyRecord(actor, record)
	if err != nil {
		return DomainRecord{}, err
	}
	owned := d.scopes[actor.Scope]
	key := d.config.ACLMetadataKey
	value, reference, err := domainRecordACLValue(key, owned, view.Records[owned.Binding.RootID], copy)
	if err != nil || !reference {
		return copy, err
	}
	template, err := cloneStagedValue(value, 0, owned.Bounds.MaxValueDepth)
	if err != nil {
		return DomainRecord{}, err
	}
	copy.Metadata[key] = template
	return copy, nil
}

func (d *domainEngine) authorizeDomainRecord(actor DomainVerified, access DomainAccess, view DomainView, record DomainRecord) error {
	copy, err := d.domainResolvedPolicyRecord(actor, view, record)
	if err != nil {
		return err
	}
	return d.policy.AuthorizeLocked(actor, access, copy)
}

func (d *domainEngine) createDomainRecordACL(actor DomainVerified, operation, kind string, record DomainRecord) (interface{}, error) {
	copy, err := d.domainPolicyRecord(actor, record)
	if err != nil {
		return nil, err
	}
	return d.policy.CreateACLLocked(actor, operation, kind, copy)
}
