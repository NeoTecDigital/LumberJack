// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "fmt"

// The access list holds the union of the families' fields and checks what a command declares. This
// checks what it would actually store, family by family, so a workload's list is exact: another
// kind, a family outside the policy, another family's column or any other metadata key is refused.
func (d *domainEngine) validateWorkloadDelta(entry *domainEntry, view stagedView, delta stagedDelta) error {
	if entry.actor.Kind != domainWorkloadKind {
		return nil
	}
	policy := d.config.WorkloadPolicy
	if policy == nil || len(delta.EnrollmentRecord)+len(delta.MappingRecord) != 0 || len(delta.Followers) != 0 {
		return fmt.Errorf("workload change outside the native store")
	}
	guard := domainWorkloadGuard{policy: policy, owned: entry.owned, key: d.config.ACLMetadataKey, records: view.Records}
	for _, create := range delta.Creates {
		if err := guard.create(create); err != nil {
			return err
		}
	}
	for _, write := range delta.Writes {
		if err := guard.write(write); err != nil {
			return err
		}
	}
	return nil
}

type domainWorkloadGuard struct {
	policy  *DomainWorkloadPolicy
	owned   DomainOwnedScope
	key     string
	records map[string]stagedRecord
}

func (g domainWorkloadGuard) field(name string) string { return g.owned.Layout.Fields[name] }

func (g domainWorkloadGuard) create(create stagedCreate) error {
	if create.Kind != g.owned.Layout.Kinds[domainWorkloadCreateKind] || create.ParentID != g.owned.Binding.RootID || len(create.Metadata) != 5 {
		return fmt.Errorf("workload may create only a store record on its root")
	}
	family, _ := create.Metadata[g.field("pngFamily")].(string)
	key, _ := create.Metadata[g.field("pngKey")].(string)
	version, _ := create.Metadata[g.field("pngVersion")].(string)
	data, valid := create.Metadata[g.field("pngData")].(map[string]interface{})
	if !valid || key == "" || version == "" || data["id"] != key || data["account_id"] != g.owned.Binding.AccountID {
		return fmt.Errorf("workload record identity invalid")
	}
	reference, isReference, err := domainACLReferenceOf(create.Metadata[g.key])
	if err != nil || !isReference || reference.RootID != g.owned.Binding.RootID || reference.Kind != domainWorkloadCreateKind {
		return fmt.Errorf("workload record must follow its kind's list")
	}
	return g.dataWithin(family, nil, data)
}

func (g domainWorkloadGuard) write(write stagedWrite) error {
	record, present := g.records[write.NodeID]
	if !present || record.Kind != g.owned.Layout.Kinds[domainWorkloadCreateKind] {
		return fmt.Errorf("workload may write only a store record")
	}
	family, _ := record.Metadata[g.field("pngFamily")].(string)
	switch write.Key {
	case g.field("pngFamily"), g.field("pngKey"):
		if !domainEqual(write.Value, record.Metadata[write.Key]) {
			return fmt.Errorf("workload cannot move a record")
		}
	case g.field("pngVersion"):
		if version, _ := write.Value.(string); version == "" {
			return fmt.Errorf("workload record version invalid")
		}
	case g.field("pngData"):
		data, valid := write.Value.(map[string]interface{})
		current, known := record.Metadata[write.Key].(map[string]interface{})
		if !valid || !known {
			return fmt.Errorf("workload record data invalid")
		}
		return g.dataWithin(family, current, data)
	default:
		return fmt.Errorf("workload metadata change denied")
	}
	return g.familyAllowed(family)
}

func (g domainWorkloadGuard) familyAllowed(family string) error {
	if !domainWorkloadFamilies[family] {
		return fmt.Errorf("workload family denied: %s", family)
	}
	if _, present := g.policy.Families[family]; !present {
		return fmt.Errorf("workload family not granted: %s", family)
	}
	return nil
}

// Every key whose value this change would set, alter or remove must be one of the family's fields.
func (g domainWorkloadGuard) dataWithin(family string, current, data map[string]interface{}) error {
	if err := g.familyAllowed(family); err != nil {
		return err
	}
	fields := g.policy.Families[family]
	for key, value := range data {
		if !domainContains(fields, key) && (current == nil || !domainWorkloadSame(current, key, value)) {
			return fmt.Errorf("workload data field denied for %s: %s", family, key)
		}
	}
	for key := range current {
		if _, kept := data[key]; !kept && !domainContains(fields, key) {
			return fmt.Errorf("workload data field denied for %s: %s", family, key)
		}
	}
	return nil
}

func domainWorkloadSame(current map[string]interface{}, key string, value interface{}) bool {
	existing, present := current[key]
	return present && domainEqual(existing, value)
}
