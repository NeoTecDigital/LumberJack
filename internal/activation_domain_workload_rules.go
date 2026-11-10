// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"unicode/utf8"
)

type boundWorkloadGuard struct {
	domainWorkloadGuard
	purpose DomainWorkloadPurpose
	grant   DomainWorkloadGrant
}

func (d *domainEngine) validateBoundWorkloadDelta(entry *domainEntry, view stagedView, delta stagedDelta) error {
	purpose, err := workloadPurposeForGrant(d.config.WorkloadPolicy, entry.actor.Workload.Grant, true)
	if err != nil {
		return err
	}
	guard := boundWorkloadGuard{domainWorkloadGuard{owned: entry.owned, key: d.config.ACLMetadataKey, records: view.Records}, purpose, entry.actor.Workload.Grant}
	for _, create := range delta.Creates {
		if err := guard.createBound(create); err != nil {
			return err
		}
	}
	changed := map[string]map[string]interface{}{}
	for _, write := range delta.Writes {
		if err := guard.collectWrite(changed, write); err != nil {
			return err
		}
	}
	for id, metadata := range changed {
		if err := guard.validateChangedRecord(guard.records[id], metadata); err != nil {
			return err
		}
	}
	return nil
}

func (g boundWorkloadGuard) createBound(create stagedCreate) error {
	family, _ := create.Metadata[g.field("pngFamily")].(string)
	rule, present := g.purpose.Families[family]
	count := 5
	if rule.Kind == "associate" {
		count = 8
	}
	if !present || create.Kind != g.owned.Layout.Kinds[rule.Kind] || create.ParentID != g.owned.Binding.RootID || len(create.Metadata) != count {
		return fmt.Errorf("workload exact native kind/root/metadata denied")
	}
	reference, isReference, err := domainACLReferenceOf(create.Metadata[g.key])
	if err != nil || !isReference || reference.RootID != g.owned.Binding.RootID || reference.Kind != rule.Kind {
		return fmt.Errorf("workload exact same-kind ACL reference required")
	}
	data, valid := create.Metadata[g.field("pngData")].(map[string]interface{})
	if !valid || g.recordIdentity(create.Metadata, data) != nil {
		return fmt.Errorf("workload record identity invalid")
	}
	if err := g.carrierMetadata(rule.Kind, create.Metadata, nil, data); err != nil {
		return err
	}
	return g.dataWithinBound(rule, nil, data)
}

func (g boundWorkloadGuard) collectWrite(changed map[string]map[string]interface{}, write stagedWrite) error {
	record, present := g.records[write.NodeID]
	if !present {
		return fmt.Errorf("workload record absent")
	}
	family, _ := record.Metadata[g.field("pngFamily")].(string)
	rule, allowed := g.purpose.Families[family]
	if !allowed || record.Kind != g.owned.Layout.Kinds[rule.Kind] {
		return fmt.Errorf("workload actual family/kind denied")
	}
	if !g.writeKeyAllowed(rule.Kind, write.Key) {
		return fmt.Errorf("workload metadata change denied")
	}
	if changed[write.NodeID] == nil {
		copy := map[string]interface{}{}
		for key, value := range record.Metadata {
			copy[key] = value
		}
		changed[write.NodeID] = copy
	}
	changed[write.NodeID][write.Key] = write.Value
	return nil
}

func (g boundWorkloadGuard) writeKeyAllowed(kind, key string) bool {
	for _, name := range []string{"pngKey", "pngFamily", "pngData", "pngVersion"} {
		if key == g.field(name) {
			return true
		}
	}
	return kind == "associate" && domainContains([]string{g.field("accountId"), g.field("label"), g.field("roleIds")}, key)
}

func (g boundWorkloadGuard) validateChangedRecord(record stagedRecord, after map[string]interface{}) error {
	before, valid := record.Metadata[g.field("pngData")].(map[string]interface{})
	data, proposed := after[g.field("pngData")].(map[string]interface{})
	if !valid || !proposed || g.recordIdentity(record.Metadata, before) != nil || g.recordIdentity(after, data) != nil {
		return fmt.Errorf("workload existing record identity invalid")
	}
	for _, name := range []string{"pngKey", "pngFamily"} {
		if !domainEqual(record.Metadata[g.field(name)], after[g.field(name)]) {
			return fmt.Errorf("workload cannot move record")
		}
	}
	rule := g.purpose.Families[after[g.field("pngFamily")].(string)]
	if err := g.carrierMetadata(rule.Kind, after, record.Metadata, data); err != nil {
		return err
	}
	return g.dataWithinBound(rule, before, data)
}

func (g boundWorkloadGuard) recordIdentity(metadata, data map[string]interface{}) error {
	key, _ := metadata[g.field("pngKey")].(string)
	version, _ := metadata[g.field("pngVersion")].(string)
	if key == "" || version == "" || data["id"] != key || data["account_id"] != g.owned.Binding.AccountID || g.grant.AccountID != g.owned.Binding.AccountID {
		return fmt.Errorf("workload immutable id/account/key required")
	}
	return nil
}

func (g boundWorkloadGuard) carrierMetadata(kind string, after, before, data map[string]interface{}) error {
	if kind != "associate" {
		return nil
	}
	if validateWorkloadCarrier(g.owned.Layout) != nil || after[g.field("accountId")] != g.owned.Binding.AccountID {
		return fmt.Errorf("workload AssociateCarrier account mismatch")
	}
	label := data[g.owned.Layout.AssociateCarrier.LabelField]
	if label == nil {
		label = *g.owned.Layout.AssociateCarrier.NullLabel
	}
	text, valid := label.(string)
	if !valid || !utf8.ValidString(text) || after[g.field("label")] != text {
		return fmt.Errorf("workload AssociateCarrier derived label mismatch")
	}
	roles := after[g.field("roleIds")]
	if before != nil {
		if !domainEqual(roles, before[g.field("roleIds")]) {
			return fmt.Errorf("workload cannot alter native roles")
		}
		return nil
	}
	raw, err := CanonicalDomainJSON(roles)
	var ids []string
	if err != nil || DecodeDomainJSON(raw, &ids) != nil || ids == nil || len(ids) != 0 {
		return fmt.Errorf("workload new AssociateCarrier roles must be empty")
	}
	return nil
}

func (g boundWorkloadGuard) dataWithinBound(rule DomainWorkloadFamily, before, data map[string]interface{}) error {
	if before != nil && rule.Rule == "alive5.messages/1" {
		return fmt.Errorf("workload messages are create only")
	}
	if before != nil && (data["id"] != before["id"] || data["account_id"] != before["account_id"]) {
		return fmt.Errorf("workload cannot change data identity")
	}
	fields := rule.CreateFields
	if before != nil {
		fields = rule.UpdateFields
	}
	for key, value := range data {
		if key == "id" || key == "account_id" || before != nil && domainWorkloadSame(before, key, value) {
			continue
		}
		if !domainContains(fields, key) || !workloadChangedValueAllowed(rule.Rule, key, before, value) {
			return fmt.Errorf("workload source-owned field denied: %s", key)
		}
	}
	for key := range before {
		if _, kept := data[key]; kept {
			continue
		}
		if key == "id" || key == "account_id" || !domainContains(fields, key) || !workloadChangedValueAllowed(rule.Rule, key, before, nil) {
			return fmt.Errorf("workload source field removal denied")
		}
	}
	return g.sourceRule(rule.Rule, before, data)
}

func workloadChangedValueAllowed(rule, key string, before map[string]interface{}, value interface{}) bool {
	if before == nil {
		return true
	}
	switch rule {
	case "alive5.messages/1":
		return false
	case "alive5.conversations/1":
		return key != "title" || workloadMissing(before, key)
	case "alive5.contacts/1":
		return workloadMissing(before, key)
	}
	return true
}

func workloadMissing(before map[string]interface{}, key string) bool {
	value, present := before[key]
	return !present || value == nil || value == ""
}

func (g boundWorkloadGuard) sourceRule(rule string, before, data map[string]interface{}) error {
	switch rule {
	case "alive5.conversations/1":
		if before == nil && data["is_archived"] != false {
			return fmt.Errorf("new workload conversation must start unarchived")
		}
	case "quickbooks.client/1":
		if data["type"] != "client" {
			return fmt.Errorf("workload Associate must be client")
		}
	case "quickbooks.observation/1":
		return g.observation(before, data)
	}
	return nil
}

func (g boundWorkloadGuard) observation(before, data map[string]interface{}) error {
	attributes, ok := data["attributes"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("workload inert observation required")
	}
	keys := []string{"contractRevision", "provider", "connectionId", "entity", "externalId", "environment", "realmId", "sourceRevision", "source", "projectedFamily", "projected"}
	raw, err := CanonicalDomainJSON(attributes)
	if err != nil {
		return err
	}
	if _, err = enrollmentShape(raw, keys, []string{"mappingConflict"}, []string{"projectedFamily"}); err != nil {
		return err
	}
	if attributes["contractRevision"] != "quickbooks-observation/1" || attributes["provider"] != "quickbooks" || attributes["connectionId"] != g.grant.ConnectionID {
		return fmt.Errorf("workload observation connection mismatch")
	}
	if err := validateWorkloadObservation(attributes); err != nil {
		return err
	}
	if before == nil {
		return nil
	}
	prior, ok := before["attributes"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("workload observation prior identity absent")
	}
	for _, key := range []string{"contractRevision", "provider", "connectionId", "entity", "externalId", "environment", "realmId"} {
		if !domainEqual(prior[key], attributes[key]) {
			return fmt.Errorf("workload observation source identity cannot move")
		}
	}
	return nil
}

func validateWorkloadObservation(a map[string]interface{}) error {
	entity, _ := a["entity"].(string)
	environment, _ := a["environment"].(string)
	revision, _ := a["sourceRevision"].(string)
	if !domainContains([]string{"Account", "Customer"}, entity) || !domainContains([]string{"sandbox", "production"}, environment) || !domainValidHash(revision) {
		return fmt.Errorf("workload observation source type invalid")
	}
	for _, key := range []string{"realmId", "externalId"} {
		value, _ := a[key].(string)
		if enrollmentIdentifiers(4096, value) != nil {
			return fmt.Errorf("workload observation bounded source identity required")
		}
	}
	if _, ok := a["source"].(map[string]interface{}); !ok {
		return fmt.Errorf("workload original source object required")
	}
	if _, ok := a["projected"].(map[string]interface{}); !ok {
		return fmt.Errorf("workload inert projection object required")
	}
	if family := a["projectedFamily"]; family != nil && family != "business:associate" && family != "business:job" {
		return fmt.Errorf("workload observation projection family denied")
	}
	if conflict, present := a["mappingConflict"]; present && conflict != true {
		return fmt.Errorf("workload observation mapping conflict invalid")
	}
	_, err := cloneStagedValue(a, 0, 8)
	return err
}
