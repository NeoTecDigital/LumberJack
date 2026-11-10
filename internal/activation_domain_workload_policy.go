// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type DomainWorkloadPurpose struct {
	Provider     string                          `json:"provider"`
	PolicyDigest string                          `json:"policyDigest"`
	Families     map[string]DomainWorkloadFamily `json:"families"`
}

type DomainWorkloadFamily struct {
	Kind         string   `json:"kind"`
	ReadFields   []string `json:"readFields"`
	CreateFields []string `json:"createFields"`
	UpdateFields []string `json:"updateFields"`
	Rule         string   `json:"rule"`
}

func (p *DomainWorkloadPolicy) UnmarshalJSON(raw []byte) error {
	var shape map[string]json.RawMessage
	if err := DecodeDomainJSON(raw, &shape); err != nil {
		return err
	}
	keys := []string{"issuer", "families"}
	var nullable []string
	if _, exists := shape["contractRevision"]; exists {
		keys = []string{"contractRevision", "installationId", "issuer", "maxLifetimeSeconds", "legacyMessaging", "purposes"}
		nullable = []string{"legacyMessaging"}
	}
	if _, err := enrollmentShape(raw, keys, nil, nullable); err != nil {
		return err
	}
	type plain DomainWorkloadPolicy
	return DecodeDomainJSON(raw, (*plain)(p))
}

func (p DomainWorkloadPolicy) MarshalJSON() ([]byte, error) {
	if p.ContractRevision == "" {
		if p.InstallationID != "" || p.MaxLifetimeSeconds != 0 || p.LegacyMessaging != nil || p.Purposes != nil {
			return nil, fmt.Errorf("mixed legacy workload policy")
		}
		return json.Marshal(map[string]interface{}{"issuer": p.Issuer, "families": p.Families})
	}
	if p.Families != nil {
		return nil, fmt.Errorf("bound workload policy cannot contain legacy families")
	}
	return json.Marshal(map[string]interface{}{"contractRevision": p.ContractRevision, "installationId": p.InstallationID, "issuer": p.Issuer, "maxLifetimeSeconds": p.MaxLifetimeSeconds, "legacyMessaging": p.LegacyMessaging, "purposes": p.Purposes})
}

func (p *DomainWorkloadPurpose) UnmarshalJSON(raw []byte) error {
	if _, err := enrollmentShape(raw, []string{"provider", "policyDigest", "families"}, nil, nil); err != nil {
		return err
	}
	type plain DomainWorkloadPurpose
	return DecodeDomainJSON(raw, (*plain)(p))
}

func (f *DomainWorkloadFamily) UnmarshalJSON(raw []byte) error {
	if _, err := enrollmentShape(raw, []string{"kind", "readFields", "createFields", "updateFields", "rule"}, nil, nil); err != nil {
		return err
	}
	type plain DomainWorkloadFamily
	return DecodeDomainJSON(raw, (*plain)(f))
}

func legacyWorkloadPolicy(p *DomainWorkloadPolicy) *DomainWorkloadPolicy {
	if p == nil || p.ContractRevision != "" && p.LegacyMessaging == nil {
		return nil
	}
	if p.ContractRevision == "" {
		return p
	}
	return &DomainWorkloadPolicy{Issuer: p.Issuer, Families: p.LegacyMessaging}
}

func validateBoundWorkloadPolicy(config DomainConfig) error {
	p := config.WorkloadPolicy
	if p.ContractRevision != domainWorkloadPolicyRevision || enrollmentIdentifiers(4096, p.InstallationID) != nil || p.Families != nil || len(p.Purposes) == 0 || len(p.Purposes) > 2 {
		return fmt.Errorf("exact installed workload policy required")
	}
	if p.MaxLifetimeSeconds <= 0 || p.MaxLifetimeSeconds > 30 || p.MaxLifetimeSeconds > config.Trust.MaxLifetimeSeconds || config.ProvisioningProfile == nil {
		return fmt.Errorf("bounded workload proof lifetime/profile required")
	}
	if !strings.HasPrefix(p.Issuer, domainWorkloadIssuerPrefix) || p.Issuer == domainWorkloadIssuerPrefix || strings.ContainsAny(p.Issuer, "\r\n") || p.Issuer == config.Trust.Issuer || p.Issuer == config.IntegrationIssuer {
		return fmt.Errorf("distinct workload issuer required")
	}
	if legacy := legacyWorkloadPolicy(p); legacy != nil {
		copy := config
		copy.WorkloadPolicy = legacy
		if err := validateDomainWorkloadPolicy(copy); err != nil {
			return err
		}
	}
	for name, purpose := range p.Purposes {
		if err := validateWorkloadPurpose(config, name, purpose); err != nil {
			return err
		}
	}
	return nil
}

func workloadPolicyDigest(p *DomainWorkloadPolicy, name string, purpose DomainWorkloadPurpose) (string, error) {
	raw, err := CanonicalDomainJSON(map[string]interface{}{"contractRevision": p.ContractRevision, "installationId": p.InstallationID, "purpose": name, "provider": purpose.Provider, "families": purpose.Families})
	return stagedHash(raw), err
}

func validateWorkloadPurpose(config DomainConfig, name string, purpose DomainWorkloadPurpose) error {
	if workloadProvider(name) == "" || purpose.Provider != workloadProvider(name) || len(purpose.Families) == 0 || len(purpose.Families) > 3 {
		return fmt.Errorf("explicit finite workload purpose required")
	}
	digest, err := workloadPolicyDigest(config.WorkloadPolicy, name, purpose)
	if err != nil || purpose.PolicyDigest != digest {
		return fmt.Errorf("workload policy digest mismatch")
	}
	for family, rule := range purpose.Families {
		if err := validateWorkloadFamily(config, name, family, rule); err != nil {
			return err
		}
	}
	if err := validateWorkloadPurposeCeilings(config.ProvisioningProfile.Layout, purpose); err != nil {
		return err
	}
	return validateWorkloadOwnerCeilings(config.ProvisioningProfile, purpose)
}

func validateWorkloadFamily(config DomainConfig, purpose, family string, rule DomainWorkloadFamily) error {
	fixed, present := workloadFamilyRules[family]
	if !present || fixed.purpose != purpose || fixed.kind != rule.Kind || fixed.rule != rule.Rule {
		return fmt.Errorf("closed workload family/kind/rule required")
	}
	if err := validateDomainWorkloadFields(rule.ReadFields, config.MaxFields); err != nil {
		return err
	}
	if !workloadSortedSubset(rule.ReadFields, strings.Fields(fixed.read)) || !workloadSortedSubset(rule.CreateFields, append(strings.Fields(fixed.create), "id", "account_id")) || !workloadSortedSubset(rule.UpdateFields, append(strings.Fields(fixed.update), "id", "account_id")) {
		return fmt.Errorf("workload materialized family ceiling exceeded")
	}
	if !enrollmentGrantSubset(rule.CreateFields, rule.ReadFields) || !enrollmentGrantSubset(rule.UpdateFields, rule.ReadFields) {
		return fmt.Errorf("workload writes require own family read fields")
	}
	if rule.Kind == "associate" {
		return validateWorkloadCarrier(config.ProvisioningProfile.Layout)
	}
	return nil
}

func workloadSortedSubset(fields, ceiling []string) bool {
	if fields == nil || !sort.StringsAreSorted(fields) || !enrollmentGrantSubset(fields, ceiling) {
		return false
	}
	for i, field := range fields {
		if field == "" || i > 0 && fields[i-1] == field {
			return false
		}
	}
	return true
}

func validateWorkloadCarrier(layout DomainLayout) error {
	p := layout.AssociateCarrier
	if p == nil || p.ContractRevision != "manifest-associate-carrier/0.1" || p.InitialRoleIDs == nil || p.Family != "business:associate" || p.NativeKind != "associate" || len(p.InitialRoleIDs) != 0 || p.NullLabel == nil || layout.Kinds["associate"] == "" {
		return fmt.Errorf("actual empty-role AssociateCarrier required")
	}
	for _, field := range []string{"accountId", "label", "roleIds"} {
		if layout.Fields[field] == "" {
			return fmt.Errorf("workload carrier field absent")
		}
	}
	return nil
}

func validateWorkloadPurposeCeilings(layout DomainLayout, purpose DomainWorkloadPurpose) error {
	for _, kind := range workloadPurposeKinds(purpose) {
		if err := validateWorkloadKindCeiling(layout, purpose, kind); err != nil {
			return err
		}
	}
	return nil
}

func validateWorkloadKindCeiling(layout DomainLayout, purpose DomainWorkloadPurpose, kind string) error {
	for _, operation := range []string{domainStoreReadOperation, nativeStoreCommand} {
		fields, err := boundWorkloadGrantFields(purpose, layout, operation, kind)
		if err != nil || !enrollmentGrantSubset(fields, layout.Profiles[operation][kind]) {
			return fmt.Errorf("workload exceeds actual owner profile for %s on %s", operation, kind)
		}
	}
	return nil
}

func workloadPurposeKinds(purpose DomainWorkloadPurpose) []string {
	kinds := []string{"root"}
	for _, family := range purpose.Families {
		if !domainContains(kinds, family.Kind) {
			kinds = append(kinds, family.Kind)
		}
	}
	sort.Strings(kinds)
	return kinds
}

// This is the native ACL representation, not a per-family authorization union.
// Input and actual-delta checks independently require each complete family request.
func boundWorkloadGrantFields(purpose DomainWorkloadPurpose, layout DomainLayout, operation, kind string) ([]string, error) {
	if layout.Kinds[kind] == "" {
		return nil, fmt.Errorf("workload native kind absent")
	}
	fields := append([]string(nil), domainWorkloadBaseFields...)
	for _, name := range []string{"pngKey", "pngFamily", "pngData", "pngVersion"} {
		if layout.Fields[name] == "" {
			return nil, fmt.Errorf("workload native store field absent")
		}
	}
	if kind == "root" && operation == nativeStoreCommand {
		fields = append(fields, "children")
	}
	if operation == nativeStoreCommand && (kind == "associate" || kind == "root" && domainContains(workloadPurposeKinds(purpose), "associate")) {
		fields = append(fields, "accountId", "label", "roleIds")
	}
	for family, rule := range purpose.Families {
		if kind != "root" && kind != rule.Kind {
			continue
		}
		fields = append(fields, "family."+family)
		for _, field := range rule.ReadFields {
			fields = append(fields, "data."+field)
		}
	}
	return workloadUniqueFields(fields), nil
}

func workloadUniqueFields(fields []string) []string {
	sort.Strings(fields)
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if len(result) == 0 || result[len(result)-1] != field {
			result = append(result, field)
		}
	}
	return result
}

func authorizeBoundWorkloadAccess(policy *DomainWorkloadPolicy, actor DomainVerified, access DomainAccess) error {
	w := actor.Workload
	if w == nil || validateWorkloadRun(*w) != nil || actor.PrincipalID != workloadPrincipal(w.Grant) || actor.SessionID != workloadSession(*w) {
		return fmt.Errorf("current workload identity invalid")
	}
	purpose, err := workloadPurposeForGrant(policy, w.Grant, true)
	if err != nil {
		return err
	}
	if access.Operation != domainStoreReadOperation && access.Operation != nativeStoreCommand || access.Reference {
		return fmt.Errorf("current workload operation/reference denied")
	}
	if access.Create && !domainContains(workloadPurposeKinds(purpose), access.Kind) || access.Create && access.Kind == "root" {
		return fmt.Errorf("current workload creation denied")
	}
	families := workloadAccessFamilies(access.Fields)
	for _, family := range families {
		if err := authorizeWorkloadFamilyFields(purpose, family, access); err != nil {
			return err
		}
	}
	for _, field := range access.Fields {
		if !workloadAccessFieldKnown(purpose, families, field, access.Kind) {
			return fmt.Errorf("current workload field denied: %s", field)
		}
	}
	return nil
}

func workloadAccessFamilies(fields []string) []string {
	families := []string{}
	for _, field := range fields {
		if family, present := strings.CutPrefix(field, "family."); present {
			families = append(families, family)
		}
	}
	return families
}

func authorizeWorkloadFamilyFields(purpose DomainWorkloadPurpose, name string, access DomainAccess) error {
	family, present := purpose.Families[name]
	if !present || access.Create && family.Kind != access.Kind {
		return fmt.Errorf("current workload family/kind denied")
	}
	// Product root intents aggregate families; per-family queries and mutations
	// were checked before this intent was constructed. Never infer write permission here.
	if len(workloadAccessFamilies(access.Fields)) > 1 {
		return nil
	}
	for _, field := range access.Fields {
		if data, present := strings.CutPrefix(field, "data."); present && !domainContains(family.ReadFields, data) {
			return fmt.Errorf("current workload family field denied")
		}
	}
	return nil
}

func workloadAccessFieldKnown(purpose DomainWorkloadPurpose, families []string, field, kind string) bool {
	if name, present := strings.CutPrefix(field, "family."); present {
		_, ok := purpose.Families[name]
		return ok
	}
	if name, present := strings.CutPrefix(field, "data."); present {
		return workloadFamilyDataKnown(purpose, families, name)
	}
	return domainContains(domainWorkloadBaseFields, field) || field == "children" || (kind == "associate" || kind == "root" && domainContains(workloadPurposeKinds(purpose), "associate")) && domainContains([]string{"accountId", "label", "roleIds"}, field)
}

func validateWorkloadOwnerCeilings(profile *DomainProvisioningProfile, purpose DomainWorkloadPurpose) error {
	for _, kind := range workloadPurposeKinds(purpose) {
		if err := validateWorkloadOwnerKind(profile, purpose, kind); err != nil {
			return err
		}
	}
	return nil
}

func validateWorkloadOwnerKind(profile *DomainProvisioningProfile, purpose DomainWorkloadPurpose, kind string) error {
	for _, operation := range []string{domainStoreReadOperation, nativeStoreCommand} {
		fields, err := boundWorkloadGrantFields(purpose, profile.Layout, operation, kind)
		held := profile.OwnerGrants[kind][operation]
		if err != nil || !enrollmentGrantSubset(fields, held.Fields) || held.WorkloadGrant != nil {
			return fmt.Errorf("workload exceeds actual owner grants")
		}
		if kind == "root" && operation == nativeStoreCommand && !enrollmentGrantSubset(domainWithout(workloadPurposeKinds(purpose), "root"), held.CreateKinds) {
			return fmt.Errorf("workload create kind exceeds actual owner grant")
		}
	}
	return nil
}

type workloadFamilyRule struct{ purpose, kind, rule, read, create, update string }

var workloadFamilyRules = map[string]workloadFamilyRule{
	"resource:png.messages":                  {"messaging.sync", "png_record", "alive5.messages/1", "account_id attachments classification_category classification_confidence classification_type contact_id contact_phone conversation_id created_at direction external_thread_id hash_key id image_description image_filepath image_items message_source message_type metadata read receiving_phone sender_id sender_name sms_error_code sms_error_message sms_status text updated_at", "attachments contact_phone conversation_id created_at direction external_thread_id hash_key message_source message_type metadata sender_id sender_name text", ""},
	"resource:png.conversations":             {"messaging.sync", "png_record", "alive5.conversations/1", "account_id archived_at archived_by contact_id contact_phone conversation_type created_at external_thread_id id is_archived last_classified_at last_message last_processed participants title unread_count updated_at", "contact_phone conversation_type created_at external_thread_id is_archived last_message participants title updated_at", "last_message title updated_at"},
	"resource:png_source.messaging.contacts": {"messaging.sync", "png_record", "alive5.contacts/1", "account_id address_line1 address_line2 alternate_phone city company_name contact_type created_at created_by email fax first_name full_name groups id is_active last_name phone quickbooks_id state tags tax_id updated_at updated_by website zip_code", "contact_type first_name last_name full_name company_name email phone is_active", "contact_type first_name last_name full_name company_name email phone is_active"},
	"business:associate":                     {"accounting.sync", "associate", "quickbooks.client/1", "account_id address_line1 address_line2 alternate_phone archived_at archived_by attributes city company_name country created_at created_by email fax first_name full_name groups id is_active last_name metadata phone quickbooks_id state tags tax_id type updated_at updated_by user_id website zip_code", "type quickbooks_id full_name company_name is_active address_line1 address_line2 city state zip_code country", "type quickbooks_id full_name company_name is_active address_line1 address_line2 city state zip_code country"},
	"business:job":                           {"accounting.sync", "png_record", "quickbooks.project/1", "account_id actual_cost actual_end_date actual_start_date adjuster_email adjuster_name adjuster_phone archived_at archived_by claim_number client_id contract_date contract_signed created_at created_by description estimated_cost estimated_end_date estimated_start_date id insurance_company job_address_line1 job_address_line2 job_city job_number job_state job_type job_zip_code photos priority project_manager_id quickbooks_id quoted_amount status tags title updated_at updated_by", "quickbooks_id title client_id job_address_line1 job_address_line2 job_city job_state job_zip_code", "quickbooks_id title client_id job_address_line1 job_address_line2 job_city job_state job_zip_code"},
	"resource:png_import":                    {"accounting.sync", "png_record", "quickbooks.observation/1", "account_id attributes id", "attributes", "attributes"},
}

func workloadFamilyDataKnown(purpose DomainWorkloadPurpose, families []string, name string) bool {
	for _, family := range families {
		if domainContains(purpose.Families[family].ReadFields, name) {
			return true
		}
	}
	return false
}
