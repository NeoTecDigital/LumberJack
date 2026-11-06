// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// A workload is a scheduled process acting for an account with no person signed in. It is its own
// kind of actor, from its own issuer, under a principal and session form no person may hold, so a
// receipt naming one cannot mean a person and a person's proof cannot become one. It holds exactly
// a store read and a store write over the families below and never any control.
const domainWorkloadKind = "workload"
const domainWorkloadPrincipalPrefix = "workload:"
const domainWorkloadSessionPrefix = "workload-session:"
const domainWorkloadIssuerPrefix = "workload-authority:"
const domainStoreReadOperation = "png.store.read"
const domainStoreContract = "png-native-store/0.1"
const domainWorkloadCreateKind = "png_record"

// The engine fixes the families. Configuration can narrow them and names their data fields.
var domainWorkloadFamilies = map[string]bool{"resource:png.messages": true, "resource:png.conversations": true, "resource:png_source.messaging.contacts": true}
var domainWorkloadBaseFields = []string{"id", "pngKey", "pngFamily", "pngData", "pngVersion"}

var domainWorkloadIdentifier = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var domainWorkloadRun = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var domainWorkloadDataField = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// DomainWorkloadPolicy is protected host configuration, never request data. Without it no workload
// is admitted and no workload control runs.
type DomainWorkloadPolicy struct {
	Issuer   string              `json:"issuer"`
	Families map[string][]string `json:"families"`
}

func validateDomainWorkloadPolicy(config DomainConfig) error {
	policy := config.WorkloadPolicy
	if policy == nil {
		return nil
	}
	if config.ProvisioningProfile == nil || !strings.HasPrefix(policy.Issuer, domainWorkloadIssuerPrefix) || policy.Issuer == domainWorkloadIssuerPrefix || strings.ContainsAny(policy.Issuer, "\r\n") {
		return fmt.Errorf("explicit workload issuer on an enrollment profile required")
	}
	if policy.Issuer == config.Trust.Issuer || policy.Issuer == config.IntegrationIssuer || len(policy.Families) == 0 {
		return fmt.Errorf("explicit distinct workload issuer and families required")
	}
	for family, fields := range policy.Families {
		if !domainWorkloadFamilies[family] {
			return fmt.Errorf("workload family outside the engine's list: %s", family)
		}
		if err := validateDomainWorkloadFields(fields, config.MaxFields); err != nil {
			return err
		}
	}
	return validateDomainWorkloadCeilings(policy, config.ProvisioningProfile.Layout)
}

func validateDomainWorkloadFields(fields []string, maximum int) error {
	if len(fields) > maximum || !domainContains(fields, "id") || !domainContains(fields, "account_id") {
		return fmt.Errorf("bounded workload data fields with id and account_id required")
	}
	seen := map[string]bool{}
	for _, field := range fields {
		if !domainWorkloadDataField.MatchString(field) || seen[field] {
			return fmt.Errorf("unique plain workload data fields required")
		}
		seen[field] = true
	}
	return nil
}

// What a workload holds can never exceed what the owner's own profile declares.
func validateDomainWorkloadCeilings(policy *DomainWorkloadPolicy, layout DomainLayout) error {
	for _, operation := range []string{domainStoreReadOperation, nativeStoreCommand} {
		for _, kind := range []string{"root", domainWorkloadCreateKind} {
			ceiling := layout.Profiles[operation][kind]
			fields, err := domainWorkloadGrantFields(policy, layout, operation, kind)
			if err != nil {
				return err
			}
			if !enrollmentGrantSubset(fields, ceiling) {
				return fmt.Errorf("workload fields exceed the owner profile for %s on %s", operation, kind)
			}
		}
	}
	return nil
}

func domainWorkloadGrantFields(policy *DomainWorkloadPolicy, layout DomainLayout, operation, kind string) ([]string, error) {
	ceiling := layout.Profiles[operation][kind]
	if !enrollmentGrantSubset(domainWorkloadBaseFields, ceiling) || layout.Kinds[kind] == "" || layout.Fields["pngFamily"] == "" || layout.Fields["pngData"] == "" || layout.Fields["pngKey"] == "" || layout.Fields["pngVersion"] == "" {
		return nil, fmt.Errorf("workload store profile absent for %s on %s", operation, kind)
	}
	set := map[string]bool{}
	for _, field := range domainWorkloadBaseFields {
		set[field] = true
	}
	if domainContains(ceiling, "children") && kind == "root" && operation == nativeStoreCommand {
		set["children"] = true
	}
	for family, fields := range policy.Families {
		set["family."+family] = true
		for _, field := range fields {
			set["data."+field] = true
		}
	}
	result := make([]string, 0, len(set))
	for field := range set {
		result = append(result, field)
	}
	sort.Strings(result)
	return result, nil
}

// The id in workload:<id>, or false for anything that is not exactly that form.
func domainWorkloadID(principal string) (string, bool) {
	id, found := strings.CutPrefix(principal, domainWorkloadPrincipalPrefix)
	return id, found && domainWorkloadIdentifier.MatchString(id)
}

// workload-session:<id>:<run>, so a session belongs to one workload.
func domainWorkloadSessionValid(id, session string) bool {
	run, found := strings.CutPrefix(session, domainWorkloadSessionPrefix+id+":")
	return found && domainWorkloadRun.MatchString(run)
}

// True for anything in, or dressed as, the reserved forms. No person may hold one, in any case.
func domainWorkloadIdentity(principal, session string) bool {
	return strings.HasPrefix(strings.ToLower(principal), domainWorkloadPrincipalPrefix) || strings.HasPrefix(strings.ToLower(session), domainWorkloadSessionPrefix)
}

func (d *domainEngine) validWorkloadActor(actor DomainVerified) bool {
	policy := d.config.WorkloadPolicy
	if policy == nil || actor.Issuer != policy.Issuer || actor.IntegrationActor != nil || actor.OwnerAuthorized || actor.PrincipalReference != nil || actor.ResolutionNamespace != nil {
		return false
	}
	id, valid := domainWorkloadID(actor.PrincipalID)
	return valid && domainWorkloadSessionValid(id, actor.SessionID) && domainWorkloadIntent(actor.Intent)
}

func domainWorkloadIntent(intent DomainIntent) bool {
	if intent.ContractRevision != domainStoreContract || intent.Scope.Product != "manifest" || intent.PrincipalID != nil || intent.TargetPrincipalID != nil {
		return false
	}
	if intent.Mode == "read" {
		return intent.Operation == nil
	}
	return intent.Mode == "command" && intent.Operation != nil && *intent.Operation == nativeStoreCommand
}

// Held regardless of what any access list says: a list naming a workload cannot widen this, and a
// list granted before the policy was narrowed stops at the policy now.
func authorizeDomainWorkloadAccess(policy *DomainWorkloadPolicy, actor DomainVerified, access DomainAccess) error {
	if id, valid := domainWorkloadID(actor.PrincipalID); policy == nil || !valid || !domainWorkloadSessionValid(id, actor.SessionID) {
		return fmt.Errorf("current workload identity invalid")
	}
	if access.Operation != domainStoreReadOperation && access.Operation != nativeStoreCommand {
		return fmt.Errorf("current workload operation denied")
	}
	if access.Reference || access.Create && access.Kind != domainWorkloadCreateKind {
		return fmt.Errorf("current workload reference/creation denied")
	}
	for _, field := range access.Fields {
		if !domainWorkloadFieldAllowed(policy, field) {
			return fmt.Errorf("current workload field denied: %s", field)
		}
	}
	return nil
}

func domainWorkloadFieldAllowed(policy *DomainWorkloadPolicy, field string) bool {
	if family, found := strings.CutPrefix(field, "family."); found {
		_, granted := policy.Families[family]
		return granted && domainWorkloadFamilies[family]
	}
	if name, found := strings.CutPrefix(field, "data."); found {
		for _, fields := range policy.Families {
			if domainContains(fields, name) {
				return true
			}
		}
		return false
	}
	return field == "children" || domainContains(domainWorkloadBaseFields, field)
}
