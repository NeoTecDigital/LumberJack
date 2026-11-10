// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const domainWorkloadPolicyRevision = "manifest-native-workload-policy/0.2"
const domainWorkloadGrantRevision = "manifest-workload-grant/0.2"
const domainWorkloadRunRevision = "manifest-workload-run/0.1"
const domainWorkloadHandoffRevision = "manifest-workload-handoff/0.1"
const workloadMaxUnixSeconds int64 = 9007199254740991

var workloadFence = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

type DomainWorkloadGrant struct {
	ContractRevision string `json:"contractRevision"`
	InstallationID   string `json:"installationId"`
	AccountID        string `json:"accountId"`
	ConnectionID     string `json:"connectionId"`
	Provider         string `json:"provider"`
	Purpose          string `json:"purpose"`
	GrantRevision    string `json:"grantRevision"`
	PolicyDigest     string `json:"policyDigest"`
	ExpiresAt        int64  `json:"expiresAt"`
}

type DomainWorkloadRun struct {
	ContractRevision string              `json:"contractRevision"`
	Grant            DomainWorkloadGrant `json:"grant"`
	RunID            string              `json:"runId"`
	FenceGeneration  string              `json:"fenceGeneration"`
}

func (g *DomainWorkloadGrant) UnmarshalJSON(raw []byte) error {
	keys := []string{"contractRevision", "installationId", "accountId", "connectionId", "provider", "purpose", "grantRevision", "policyDigest", "expiresAt"}
	if _, err := enrollmentShape(raw, keys, nil, nil); err != nil {
		return err
	}
	type plain DomainWorkloadGrant
	if err := DecodeDomainJSON(raw, (*plain)(g)); err != nil {
		return err
	}
	return validateWorkloadGrant(*g)
}

func validateWorkloadGrant(g DomainWorkloadGrant) error {
	if g.ContractRevision != domainWorkloadGrantRevision || g.ExpiresAt <= 0 || g.ExpiresAt > workloadMaxUnixSeconds || !domainValidHash(g.PolicyDigest) {
		return fmt.Errorf("exact workload grant revision/integer expiry/digest required")
	}
	if enrollmentIdentifiers(4096, g.InstallationID, g.AccountID, g.ConnectionID, g.GrantRevision) != nil || workloadProvider(g.Purpose) != g.Provider || g.Provider == "" {
		return fmt.Errorf("bounded exact workload tuple required")
	}
	return nil
}

func (w *DomainWorkloadRun) UnmarshalJSON(raw []byte) error {
	if _, err := enrollmentShape(raw, []string{"contractRevision", "grant", "runId", "fenceGeneration"}, nil, nil); err != nil {
		return err
	}
	type plain DomainWorkloadRun
	if err := DecodeDomainJSON(raw, (*plain)(w)); err != nil {
		return err
	}
	return validateWorkloadRun(*w)
}

func validateWorkloadRun(w DomainWorkloadRun) error {
	if w.ContractRevision != domainWorkloadRunRevision || !domainWorkloadRun.MatchString(w.RunID) || !workloadFence.MatchString(w.FenceGeneration) {
		return fmt.Errorf("exact workload run/canonical positive fence required")
	}
	if _, err := strconv.ParseUint(w.FenceGeneration, 10, 64); err != nil {
		return fmt.Errorf("workload fence exceeds uint64")
	}
	return validateWorkloadGrant(w.Grant)
}

func workloadProvider(purpose string) string {
	switch purpose {
	case "messaging.sync":
		return "alive5"
	case "accounting.sync":
		return "quickbooks"
	}
	return ""
}

func workloadPrincipal(g DomainWorkloadGrant) string {
	raw, _ := CanonicalDomainJSON(map[string]string{"installationId": g.InstallationID, "accountId": g.AccountID, "connectionId": g.ConnectionID, "provider": g.Provider, "purpose": g.Purpose})
	return domainWorkloadPrincipalPrefix + stagedHash(raw)
}

func workloadSession(w DomainWorkloadRun) string {
	return domainWorkloadSessionPrefix + strings.TrimPrefix(workloadPrincipal(w.Grant), domainWorkloadPrincipalPrefix) + ":" + w.RunID
}

func workloadPurposeForGrant(policy *DomainWorkloadPolicy, g DomainWorkloadGrant, current bool) (DomainWorkloadPurpose, error) {
	if validateWorkloadGrant(g) != nil || policy == nil || policy.ContractRevision != domainWorkloadPolicyRevision || policy.InstallationID != g.InstallationID {
		return DomainWorkloadPurpose{}, fmt.Errorf("registered workload installation/grant required")
	}
	purpose, present := policy.Purposes[g.Purpose]
	if !present || purpose.Provider != g.Provider || purpose.PolicyDigest != g.PolicyDigest || current && float64(g.ExpiresAt) <= domainNow() {
		return DomainWorkloadPurpose{}, fmt.Errorf("current workload purpose/digest/expiry denied")
	}
	return purpose, nil
}

func (d *domainEngine) bindWorkloadIntent(input DomainInput, intent *DomainIntent) error {
	if intent.Workload != nil {
		return fmt.Errorf("product cannot supply workload authority")
	}
	if input.Workload == nil {
		return nil
	}
	w := input.Workload
	if validateWorkloadRun(*w) != nil || w.Grant.AccountID != intent.Scope.AccountID || input.ResolutionNamespace != nil || !domainWorkloadIntent(*intent) {
		return fmt.Errorf("workload input/intent tuple mismatch")
	}
	purpose, err := workloadPurposeForGrant(d.config.WorkloadPolicy, w.Grant, true)
	if err != nil {
		return err
	}
	if err = validateBoundWorkloadInput(input, purpose); err != nil {
		return err
	}
	raw, err := CanonicalDomainJSON(w)
	if err != nil {
		return err
	}
	var copy DomainWorkloadRun
	if err = DecodeDomainJSON(raw, &copy); err != nil {
		return err
	}
	intent.Workload = &copy
	return nil
}

func (d *domainEngine) validBoundWorkloadActor(actor DomainVerified) bool {
	w := actor.Workload
	if w == nil || !domainWorkloadIntent(actor.Intent) || validateWorkloadRun(*w) != nil || !domainEqual(w, actor.Intent.Workload) || actor.PrincipalID != workloadPrincipal(w.Grant) || actor.SessionID != workloadSession(*w) {
		return false
	}
	p := d.config.WorkloadPolicy
	if _, err := workloadPurposeForGrant(p, w.Grant, true); err != nil || actor.Scope.AccountID != w.Grant.AccountID || actor.GrantRevision != w.Grant.GrantRevision {
		return false
	}
	return actor.ContractRevision == domainWorkloadHandoffRevision && actor.ExpiresAt <= float64(w.Grant.ExpiresAt) && actor.ExpiresAt <= domainNow()+float64(p.MaxLifetimeSeconds)
}

func workloadGrantMatches(actor DomainVerified, grant domainGrant) bool {
	if actor.Workload == nil {
		return grant.WorkloadGrant == nil
	}
	g := actor.Workload.Grant
	return actor.Kind == domainWorkloadKind && grant.WorkloadGrant != nil && domainEqual(*grant.WorkloadGrant, g) && actor.GrantRevision == g.GrantRevision && grant.TargetGrantRevision == g.GrantRevision && float64(g.ExpiresAt) > domainNow()
}

func validateWorkloadACL(acl domainACL) error {
	for principal, grants := range acl.Principals {
		if err := validateWorkloadACLGrants(acl.ContractRevision, principal, grants); err != nil {
			return err
		}
	}
	for _, contribution := range acl.Coowners {
		if err := validateWorkloadACLGrants("", "", contribution.Grants); err != nil {
			return err
		}
	}
	for _, template := range acl.CreateACLs {
		if err := validateWorkloadACL(template); err != nil {
			return err
		}
	}
	return nil
}

func validateWorkloadACLGrants(revision, principal string, grants map[string]domainGrant) error {
	for operation, grant := range grants {
		if grant.WorkloadGrant == nil {
			continue
		}
		g := *grant.WorkloadGrant
		if revision != domainCoownerACLRevision || validateWorkloadGrant(g) != nil || principal != workloadPrincipal(g) || grant.TargetGrantRevision != g.GrantRevision || grant.Reference || !domainContains([]string{domainStoreReadOperation, nativeStoreCommand}, operation) {
			return fmt.Errorf("workload grant is only valid on exact reserved ACL/2 store contribution")
		}
	}
	return nil
}

// Fixed input vocabularies are validated by the actual product first; here every
// query/mutation is checked independently rather than using its aggregate intent.
func validateBoundWorkloadInput(input DomainInput, purpose DomainWorkloadPurpose) error {
	var request workloadStoreInput
	if err := json.Unmarshal(input.Body, &request); err != nil {
		return err
	}
	if len(request.References) != 0 {
		return fmt.Errorf("workload cannot request references")
	}
	if input.Mode == "read" {
		return validateWorkloadQuery(request.Query, purpose)
	}
	if err := validateBoundWorkloadResult(request.Result); err != nil {
		return err
	}
	for _, mutation := range request.Mutations {
		family, present := purpose.Families[mutation.Family]
		if !present || !workloadDataSubset(mutation.Data, family.ReadFields) {
			return fmt.Errorf("workload mutation outside its own family's read ceiling")
		}
	}
	for _, unique := range request.Unique {
		family, present := purpose.Families[unique.Family]
		if !present || !workloadDataSubset(unique.Fields, family.ReadFields) {
			return fmt.Errorf("workload uniqueness outside its own family")
		}
	}
	return nil
}

type workloadStoreInput struct {
	Result     json.RawMessage    `json:"result"`
	Query      workloadStoreQuery `json:"query"`
	References []json.RawMessage  `json:"references"`
	Mutations  []struct {
		Family string                 `json:"family"`
		Data   map[string]interface{} `json:"data"`
	} `json:"mutations"`
	Unique []struct {
		Family string                 `json:"family"`
		Fields map[string]interface{} `json:"fields"`
	} `json:"unique"`
}

type workloadStoreQuery struct {
	Family  string   `json:"family"`
	Fields  []string `json:"fields"`
	OrderBy []string `json:"order_by"`
	Filters []struct {
		Field string `json:"field"`
	} `json:"filters"`
}

func validateWorkloadQuery(query workloadStoreQuery, purpose DomainWorkloadPurpose) error {
	family, present := purpose.Families[query.Family]
	if !present || len(query.Fields) == 0 || !enrollmentGrantSubset(query.Fields, family.ReadFields) {
		return fmt.Errorf("explicit whole workload query exceeds its family read ceiling")
	}
	for _, field := range query.OrderBy {
		if !domainContains(family.ReadFields, strings.TrimPrefix(field, "-")) {
			return fmt.Errorf("workload ordering exceeds its family read ceiling")
		}
	}
	for _, filter := range query.Filters {
		if !domainContains(family.ReadFields, filter.Field) {
			return fmt.Errorf("workload filter exceeds its family read ceiling")
		}
	}
	return nil
}

func workloadDataSubset(data map[string]interface{}, fields []string) bool {
	for key := range data {
		if !domainContains(fields, key) {
			return false
		}
	}
	return true
}

func workloadHandoffRevision(intent DomainIntent) string {
	if intent.Workload != nil {
		return domainWorkloadHandoffRevision
	}
	return DomainRevision
}

func decodeWorkloadAnswer(raw []byte, intent DomainIntent, actor *DomainVerified) error {
	if intent.Workload != nil {
		keys := []string{"contractRevision", "principalId", "kind", "sessionId", "scope", "intent", "grantRevision", "authorityResourceRevision", "expiresAt", "issuer", "audience", "phase", "leaseBinding", "proofBinding", "workload"}
		if _, err := enrollmentShape(raw, keys, nil, []string{"leaseBinding"}); err != nil {
			return err
		}
	}
	return DecodeDomainJSON(raw, actor)
}

func (d *domainEngine) refreshWorkloadDeadline(entry *domainEntry, actor *DomainVerified) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if entry.actor.Workload == nil && actor.Workload == nil {
		return nil
	}
	if entry.actor.Workload == nil || actor.Workload == nil || !domainEqual(entry.actor.Workload, actor.Workload) || workloadLeaseDeadlineLocked(entry) <= domainNow() {
		return fmt.Errorf("original workload lease expired/rebound")
	}
	if maximum := workloadLeaseDeadlineLocked(entry); actor.ExpiresAt > maximum {
		actor.ExpiresAt = maximum
	}
	entry.workloadDeadline = actor.ExpiresAt
	return nil
}

func validateBoundWorkloadResult(raw json.RawMessage) error {
	if len(raw) == 0 || enrollmentNull(raw) {
		return nil
	}
	shape, err := enrollmentShape(raw, nil, []string{"command_digest"}, nil)
	if err != nil {
		return fmt.Errorf("workload cannot request derivation/approval result effects")
	}
	if digest, present := shape["command_digest"]; present {
		var value string
		if DecodeDomainJSON(digest, &value) != nil || !domainValidHash(value) {
			return fmt.Errorf("exact workload command digest required")
		}
	}
	return nil
}

func workloadLeaseDeadlineLocked(entry *domainEntry) float64 {
	until := entry.actor.ExpiresAt
	if entry.actor.Workload != nil && entry.workloadDeadline > 0 && entry.workloadDeadline < until {
		until = entry.workloadDeadline
	}
	return until
}

func (d *domainEngine) workloadLeaseLive(entry *domainEntry) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return workloadLeaseDeadlineLocked(entry) > domainNow()
}
