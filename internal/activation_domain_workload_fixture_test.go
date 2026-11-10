// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

const (
	wlPrincipal     = "workload:alive5-sync"
	wlSession       = "workload-session:alive5-sync:run-1"
	wlIssuer        = "workload-authority:unit"
	wlMessages      = "resource:png.messages"
	wlConversations = "resource:png.conversations"
	wlContacts      = "resource:png_source.messaging.contacts"
	wlOtherFamily   = "business:job"
	wlRevision      = "unit-accepted-actor-permission-1"
	wlNewRevision   = "unit-workload-revision-2"
)

var wlFamilyFields = map[string][]string{
	wlMessages:      {"id", "account_id", "text", "direction"},
	wlConversations: {"id", "account_id", "title", "unread_count"},
	wlContacts:      {"id", "account_id", "phone"},
}

func wlPolicy() *DomainWorkloadPolicy {
	return &DomainWorkloadPolicy{Issuer: wlIssuer, Families: wlFamilyFields}
}

// The fixture profile with a store on it: a ceiling wider than the workload's list, as a real one is.
func wlStoreCeiling(kind string, write bool) []string {
	fields := []string{"id", "pngKey", "pngFamily", "pngData", "pngVersion", "reference", "family." + wlMessages, "family." + wlConversations, "family." + wlContacts, "family." + wlOtherFamily, "data.id", "data.account_id", "data.text", "data.direction", "data.title", "data.unread_count", "data.phone", "data.salary"}
	if kind == "root" && write {
		fields = append(fields, "children")
	}
	return fields
}

func wlFixtureConfig(t *testing.T) DomainConfig {
	t.Helper()
	config := enrollmentFixtureConfig(t)
	config.MaxFields = 64
	p := config.ProvisioningProfile
	p.Layout.Kinds["png_record"] = "unit-native-png_record"
	for _, field := range []string{"pngKey", "pngFamily", "pngData", "pngVersion"} {
		p.Layout.Fields[field] = field
	}
	p.Layout.Profiles["read"]["png_record"] = []string{"id"}
	p.OwnerGrants["png_record"] = map[string]domainGrant{"read": {Fields: []string{"id"}}}
	for _, operation := range []string{domainStoreReadOperation, nativeStoreCommand} {
		write := operation == nativeStoreCommand
		p.Layout.Routes[operation] = DomainRoute{Method: "POST", Target: "/unit/" + operation}
		p.Layout.Profiles[operation] = map[string][]string{"root": wlStoreCeiling("root", write), "png_record": wlStoreCeiling("png_record", write)}
		p.OwnerGrants["root"][operation] = domainGrant{Fields: wlStoreCeiling("root", write), Reference: true}
		p.OwnerGrants["png_record"][operation] = domainGrant{Fields: wlStoreCeiling("png_record", write), Reference: true}
	}
	write := p.OwnerGrants["root"][nativeStoreCommand]
	write.CreateKinds = []string{"png_record"}
	p.OwnerGrants["root"][nativeStoreCommand] = write
	digest, err := DomainProvisioningProfileDigest(*p)
	if err != nil {
		t.Fatal(err)
	}
	p.ProfileRef.ProfileDigest = digest
	config.WorkloadPolicy = wlPolicy()
	return config
}

func newWorkloadFixture(t *testing.T) *enrollmentFixture {
	t.Helper()
	return newEnrollmentFixtureWith(t, wlFixtureConfig(t))
}

func wlSeed(t *testing.T, f *enrollmentFixture, rootID, id, family string, value interface{}) {
	t.Helper()
	f.server.forestMutex.Lock()
	defer f.server.forestMutex.Unlock()
	root, err := f.server.forest.GetNode(rootID)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor stagedDescriptor
	if err = decodeStagedInternal(root.CommandReceipts[stagedScopeKey], &descriptor); err != nil {
		t.Fatal(err)
	}
	data := map[string]interface{}{"id": id, "account_id": root.Metadata["accountId"]}
	metadata := map[string]interface{}{f.config.ACLMetadataKey: value, "pngKey": id, "pngFamily": family, "pngData": data, "pngVersion": "labelled-version"}
	root.Children[id] = &core.Node{ID: id, Name: id, Kind: f.config.ProvisioningProfile.Layout.Kinds["png_record"], Parents: map[string]string{root.ID: root.Name}, Children: map[string]*core.Node{}, Metadata: metadata, CommandReceipts: map[string]interface{}{stagedScopeKey: descriptor}}
}

func wlTemplateCopy(t *testing.T, f *enrollmentFixture, rootID string) interface{} {
	t.Helper()
	root, err := f.server.forest.GetNode(rootID)
	if err != nil {
		t.Fatal(err)
	}
	policy := &domainOwnerPolicy{key: f.config.ACLMetadataKey}
	value, err := legacyCreateACL(policy, DomainVerified{PrincipalID: aclFixtureOwner}, nativeStoreCommand, "png_record", DomainRecord{ID: rootID, Metadata: root.Metadata})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func wlActor(f *enrollmentFixture, account, revision string) DomainVerified {
	return DomainVerified{PrincipalID: wlPrincipal, Kind: domainWorkloadKind, SessionID: wlSession, Issuer: wlIssuer, GrantRevision: revision, ExpiresAt: domainNow() + 30, Scope: DomainScope{AccountID: account, Product: "manifest"}}
}

func wlDecide(t *testing.T, f *enrollmentFixture, actor DomainVerified, access DomainAccess, id string) error {
	t.Helper()
	d := f.server.domain
	owned := d.scopes[actor.Scope]
	f.server.forestMutex.RLock()
	defer f.server.forestMutex.RUnlock()
	view, err := f.server.domainScopeViewLocked(owned, false, true)
	if err != nil {
		t.Fatal(err)
	}
	return d.authorizeDomainRecord(actor, access, view, view.Records[id])
}

func wlStoreAccess(operation, family string) DomainAccess {
	return DomainAccess{Operation: operation, Fields: []string{"id", "pngFamily", "family." + family, "data.id"}}
}

func wlEnroll(t *testing.T, f *enrollmentFixture, operation, account, rootID, target, tag string) DomainBegin {
	t.Helper()
	begin := f.enroll(t, f.input(operation, account, "unit-"+tag, "unit-proof-"+tag, enrollmentCurrentRevision(t, f, rootID), &target))
	enrollmentAssertAppliedPair(t, f.received(t, begin), begin, "applied")
	return begin
}

func wlEnrollRefused(t *testing.T, f *enrollmentFixture, operation, account, rootID, target, tag string) error {
	t.Helper()
	input := f.input(operation, account, "unit-"+tag, "unit-proof-"+tag, enrollmentCurrentRevision(t, f, rootID), &target)
	raw, err := CanonicalDomainJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.server.DomainEnrollJSON(contextBackground(), raw); err == nil {
		t.Fatalf("%s for %s was accepted", operation, target)
	}
	return err
}

func wlRootACL(t *testing.T, f *enrollmentFixture, rootID string) domainACL {
	t.Helper()
	root, err := f.server.forest.GetNode(rootID)
	if err != nil {
		t.Fatal(err)
	}
	policy := &domainOwnerPolicy{key: f.config.ACLMetadataKey}
	acl, err := policy.acl(DomainRecord{ID: root.ID, Metadata: root.Metadata})
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

func wbPolicy() *DomainWorkloadPolicy {
	p := &DomainWorkloadPolicy{ContractRevision: domainWorkloadPolicyRevision, InstallationID: "labelled-installation", Issuer: wlIssuer, MaxLifetimeSeconds: 30, Purposes: map[string]DomainWorkloadPurpose{}}
	for _, purpose := range []string{"messaging.sync", "accounting.sync"} {
		p.Purposes[purpose] = wbPurpose(purpose)
	}
	for name, purpose := range p.Purposes {
		purpose.PolicyDigest, _ = workloadPolicyDigest(p, name, purpose)
		p.Purposes[name] = purpose
	}
	return p
}

func wbPurpose(name string) DomainWorkloadPurpose {
	p := DomainWorkloadPurpose{Provider: workloadProvider(name), Families: map[string]DomainWorkloadFamily{}}
	for family, fixed := range workloadFamilyRules {
		if fixed.purpose != name {
			continue
		}
		read := strings.Fields(fixed.read)
		create := append(strings.Fields(fixed.create), "id", "account_id")
		update := append(strings.Fields(fixed.update), "id", "account_id")
		sort.Strings(read)
		sort.Strings(create)
		sort.Strings(update)
		p.Families[family] = DomainWorkloadFamily{fixed.kind, read, create, update, fixed.rule}
	}
	return p
}

func wbGrant(account, purpose string) DomainWorkloadGrant {
	p := wbPolicy()
	return DomainWorkloadGrant{domainWorkloadGrantRevision, p.InstallationID, account, "labelled-connection", workloadProvider(purpose), purpose, "labelled-G1", p.Purposes[purpose].PolicyDigest, 4102444800}
}

func wbConfig(t *testing.T) DomainConfig {
	t.Helper()
	config := wlFixtureConfig(t)
	config.MaxFields = 1024
	p := config.ProvisioningProfile
	empty := ""
	p.Layout.AssociateCarrier = &DomainAssociateCarrierPolicy{ContractRevision: "manifest-associate-carrier/0.1", Family: "business:associate", NativeKind: "associate", LabelField: "full_name", NullLabel: &empty, InitialRoleIDs: []string{}}
	config.WorkloadPolicy = wbPolicy()
	for _, purpose := range config.WorkloadPolicy.Purposes {
		wbOwnerCeilings(p, purpose)
	}
	digest, err := DomainProvisioningProfileDigest(*p)
	if err != nil {
		t.Fatal(err)
	}
	p.ProfileRef.ProfileDigest = digest
	return config
}

// Synthetic test profile only. Production masks are never widened by installation.
func wbOwnerCeilings(p *DomainProvisioningProfile, purpose DomainWorkloadPurpose) {
	for _, kind := range workloadPurposeKinds(purpose) {
		wbOwnerKindCeiling(p, purpose, kind)
	}
}

func wbOwnerKindCeiling(p *DomainProvisioningProfile, purpose DomainWorkloadPurpose, kind string) {
	for _, operation := range []string{domainStoreReadOperation, nativeStoreCommand} {
		fields, _ := boundWorkloadGrantFields(purpose, p.Layout, operation, kind)
		fields = workloadUniqueFields(append(fields, p.Layout.Profiles[operation][kind]...))
		p.Layout.Profiles[operation][kind] = fields
		held := p.OwnerGrants[kind][operation]
		held.Fields = fields
		if kind == "root" && operation == nativeStoreCommand {
			held.CreateKinds = []string{"associate", "png_record"}
		}
		p.OwnerGrants[kind][operation] = held
	}
}

func newBoundWorkloadFixture(t *testing.T) *enrollmentFixture {
	t.Helper()
	f := &enrollmentFixture{server: stagedTestServer(t, t.TempDir()), config: wbConfig(t), seen: map[string]bool{}, session: "unit-current-session", claim: "unit-owner-claim-1", targetRevision: "labelled-G1", targetState: "active"}
	if err := f.server.configureStagedScope(stagedTestBinding(), stagedTestBounds()); err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { wbEnrollmentCallback(f, w, r) }))
	t.Cleanup(callback.Close)
	f.config.Trust.VerifierEndpoint = callback.URL + "/labelled-workload-authority"
	policy, err := NewDomainOwnerPolicy(f.config.ACLMetadataKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.server.ConfigureDomain(f.config, map[string]DomainProduct{"manifest": domainTestProduct{}}, policy); err != nil {
		t.Fatal(err)
	}
	return f
}

func wbEnrollmentCallback(f *enrollmentFixture, w http.ResponseWriter, r *http.Request) {
	var check EnrollmentCheck
	if json.NewDecoder(r.Body).Decode(&check) != nil || r.Header.Get("Authorization") != "Bearer "+f.config.Trust.ChannelToken {
		w.WriteHeader(403)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen[check.Proof] {
		w.WriteHeader(403)
		return
	}
	f.seen[check.Proof] = true
	actor := f.actor(check)
	actor.ContractRevision = enrollmentProofRevision(check.Request)
	raw, _ := CanonicalDomainJSON(actor)
	var value map[string]interface{}
	_ = DecodeDomainJSON(raw, &value)
	if boundWorkloadEnrollment(check.Request) {
		value["administratorAuthorized"] = false
	}
	_ = json.NewEncoder(w).Encode(value)
}

func wbInput(t *testing.T, f *enrollmentFixture, root string, g DomainWorkloadGrant, operation, tag string) EnrollmentInput {
	t.Helper()
	target := workloadPrincipal(g)
	input := f.input(operation, g.AccountID, "labelled-"+tag, "labelled_"+strings.ReplaceAll(tag, "-", "_"), enrollmentCurrentRevision(t, f, root), &target)
	input.ContractRevision, input.Request.ContractRevision = EnrollmentBoundWorkloadProofRevision, EnrollmentBoundWorkloadRevision
	input.Request.WorkloadGrant = &g
	return input
}
