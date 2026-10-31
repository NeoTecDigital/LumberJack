// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"strings"
	"testing"
)

func contextBackground() context.Context { return context.Background() }

func wlEngine() *domainEngine {
	return &domainEngine{config: DomainConfig{Trust: ActivationConfig{Issuer: "unit-person-issuer"}, IntegrationIssuer: "channel-integration:unit", WorkloadPolicy: wlPolicy()}}
}

func wlValidActor() DomainVerified {
	return DomainVerified{Kind: domainWorkloadKind, PrincipalID: wlPrincipal, SessionID: wlSession, Issuer: wlIssuer, Intent: DomainIntent{ContractRevision: domainStoreContract, Mode: "read", Scope: DomainScope{AccountID: "a", Product: "manifest"}}}
}

func TestWorkloadActorFormsFailClosed(t *testing.T) {
	write := nativeStoreCommand
	other := "role.define"
	target := "someone"
	cases := []struct {
		name   string
		mutate func(*DomainVerified)
		valid  bool
	}{
		{"exact read", func(a *DomainVerified) {}, true},
		{"exact write", func(a *DomainVerified) { a.Intent.Mode, a.Intent.Operation = "command", &write }, true},
		{"person issuer", func(a *DomainVerified) { a.Issuer = "unit-person-issuer" }, false},
		{"integration issuer", func(a *DomainVerified) { a.Issuer = "channel-integration:unit" }, false},
		{"other issuer", func(a *DomainVerified) { a.Issuer = "workload-authority:other" }, false},
		{"bare prefix", func(a *DomainVerified) { a.PrincipalID, a.SessionID = "workload:", "workload-session::r" }, false},
		{"upper case", func(a *DomainVerified) { a.PrincipalID = "workload:ALIVE5" }, false},
		{"upper prefix", func(a *DomainVerified) { a.PrincipalID = "WORKLOAD:alive5-sync" }, false},
		{"space", func(a *DomainVerified) { a.PrincipalID = "workload:alive5 sync" }, false},
		{"colon in id", func(a *DomainVerified) { a.PrincipalID = "workload:alive5:sync" }, false},
		{"newline", func(a *DomainVerified) { a.PrincipalID = "workload:alive5\n" }, false},
		{"too long", func(a *DomainVerified) { a.PrincipalID = "workload:" + strings.Repeat("a", 65) }, false},
		{"person principal", func(a *DomainVerified) { a.PrincipalID = "user-1" }, false},
		{"associate principal", func(a *DomainVerified) { a.PrincipalID = "associate:1" }, false},
		{"message session", func(a *DomainVerified) { a.SessionID = "channel-message:1" }, false},
		{"person session", func(a *DomainVerified) { a.SessionID = "unit-current-session" }, false},
		{"another workload's session", func(a *DomainVerified) { a.SessionID = "workload-session:other:run-1" }, false},
		{"no run", func(a *DomainVerified) { a.SessionID = "workload-session:alive5-sync:" }, false},
		{"no run separator", func(a *DomainVerified) { a.SessionID = "workload-session:alive5-sync" }, false},
		{"run with a slash", func(a *DomainVerified) { a.SessionID = "workload-session:alive5-sync:a/b" }, false},
		{"owner claim", func(a *DomainVerified) { a.OwnerAuthorized = true }, false},
		{"principal reference", func(a *DomainVerified) { a.PrincipalReference = &DomainPrincipalReference{} }, false},
		{"integration profile", func(a *DomainVerified) { a.IntegrationActor = &DomainIntegrationActor{} }, false},
		{"resolution namespace", func(a *DomainVerified) { a.ResolutionNamespace = &DomainResolutionNamespace{} }, false},
		{"graph contract", func(a *DomainVerified) { a.Intent.ContractRevision = "manifest-associates/0.2" }, false},
		{"other product", func(a *DomainVerified) { a.Intent.Scope.Product = "momentum" }, false},
		{"other operation", func(a *DomainVerified) { a.Intent.Mode, a.Intent.Operation = "command", &other }, false},
		{"command without operation", func(a *DomainVerified) { a.Intent.Mode = "command" }, false},
		{"read naming an operation", func(a *DomainVerified) { a.Intent.Operation = &write }, false},
		{"target principal", func(a *DomainVerified) { a.Intent.TargetPrincipalID = &target }, false},
		{"intent principal", func(a *DomainVerified) { a.Intent.PrincipalID = &target }, false},
	}
	d := wlEngine()
	for _, item := range cases {
		actor := wlValidActor()
		item.mutate(&actor)
		if d.validDomainActorKind(actor) != item.valid {
			t.Fatalf("%s: want valid=%v", item.name, item.valid)
		}
	}
}

func TestWorkloadRefusedWithoutItsPolicy(t *testing.T) {
	d := wlEngine()
	d.config.WorkloadPolicy = nil
	if d.validDomainActorKind(wlValidActor()) {
		t.Fatal("a workload was admitted with no policy")
	}
}

// A person's proof can never be a workload's identity, in any spelling.
func TestPersonCannotHoldAWorkloadIdentity(t *testing.T) {
	d := wlEngine()
	person := func(principal, session string) DomainVerified {
		return DomainVerified{Kind: "human", PrincipalID: principal, SessionID: session, Issuer: "unit-person-issuer"}
	}
	if !d.validDomainActorKind(person("user-1", "session-1")) {
		t.Fatal("an ordinary person was refused")
	}
	for _, item := range [][2]string{{wlPrincipal, "session-1"}, {"WORKLOAD:alive5-sync", "session-1"}, {"workload:", "session-1"}, {"user-1", wlSession}, {"user-1", "Workload-Session:alive5-sync:r"}} {
		if d.validDomainActorKind(person(item[0], item[1])) {
			t.Fatalf("a person held the workload identity %v", item)
		}
	}
	integration := DomainVerified{Kind: "integration_actor", PrincipalID: wlPrincipal, SessionID: wlSession, Issuer: "channel-integration:unit", IntegrationActor: &DomainIntegrationActor{}}
	if d.validDomainActorKind(integration) {
		t.Fatal("an integration actor held a workload identity")
	}
}

func TestWorkloadPolicyValidationFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*DomainConfig)
		want   string
	}{
		{"valid", func(c *DomainConfig) {}, ""},
		{"narrower", func(c *DomainConfig) {
			c.WorkloadPolicy.Families = map[string][]string{wlMessages: wlFamilyFields[wlMessages]}
		}, ""},
		{"no issuer prefix", func(c *DomainConfig) { c.WorkloadPolicy.Issuer = "unit" }, "explicit workload issuer"},
		{"bare issuer", func(c *DomainConfig) { c.WorkloadPolicy.Issuer = domainWorkloadIssuerPrefix }, "explicit workload issuer"},
		{"newline issuer", func(c *DomainConfig) { c.WorkloadPolicy.Issuer = wlIssuer + "\n" }, "explicit workload issuer"},
		{"person issuer", func(c *DomainConfig) { c.Trust.Issuer = wlIssuer }, "distinct"},
		{"no families", func(c *DomainConfig) { c.WorkloadPolicy.Families = nil }, "distinct"},
		{"another family", func(c *DomainConfig) {
			c.WorkloadPolicy.Families = map[string][]string{wlOtherFamily: {"id", "account_id"}}
		}, "outside the engine's list"},
		{"no id", func(c *DomainConfig) {
			c.WorkloadPolicy.Families = map[string][]string{wlMessages: {"account_id", "text"}}
		}, "id and account_id"},
		{"dressed field", func(c *DomainConfig) {
			c.WorkloadPolicy.Families = map[string][]string{wlMessages: {"id", "account_id", "family.business:job"}}
		}, "plain workload data"},
		{"duplicate field", func(c *DomainConfig) {
			c.WorkloadPolicy.Families = map[string][]string{wlMessages: {"id", "account_id", "id"}}
		}, "plain workload data"},
		{"field outside the owner profile", func(c *DomainConfig) {
			c.WorkloadPolicy.Families = map[string][]string{wlMessages: {"id", "account_id", "not_in_the_ceiling"}}
		}, "exceed the owner profile"},
		{"no enrollment profile", func(c *DomainConfig) { c.ProvisioningProfile = nil }, "explicit workload issuer"},
	}
	for _, item := range cases {
		config := wlFixtureConfig(t)
		config.WorkloadPolicy = wlPolicy()
		item.mutate(&config)
		err := validateDomainWorkloadPolicy(config)
		if item.want == "" && err != nil || item.want != "" && (err == nil || !strings.Contains(err.Error(), item.want)) {
			t.Fatalf("%s: got %v, want %q", item.name, err, item.want)
		}
	}
}

// Everyone who is not a workload is admitted or refused exactly as before, with a policy configured.
func TestWorkloadPolicyLeavesEveryOtherActorAsItWas(t *testing.T) {
	configured, plain := wlEngine(), wlEngine()
	plain.config.WorkloadPolicy = nil
	associate := "person-1"
	valid := &DomainIntegrationActor{IntegrationID: "i", ConnectorID: "c", MessageID: "m", MessageHash: strings.Repeat("a", 64), CredentialRevision: "cr", PolicyRevision: "p", RosterRevision: "r", SenderPhone: "15550100"}
	withAssociate := *valid
	withAssociate.EffectiveAssociateID = &associate
	badPhone := *valid
	badPhone.SenderPhone = "not-digits"
	actors := []DomainVerified{
		{Kind: "human", Issuer: "unit-person-issuer", PrincipalID: "user-1", SessionID: "s"},
		{Kind: "human", Issuer: "another-issuer", PrincipalID: "user-1", SessionID: "s"},
		{Kind: "human", Issuer: "unit-person-issuer", PrincipalID: "user-1", SessionID: "s", IntegrationActor: valid},
		{Kind: "integration_actor", Issuer: "channel-integration:unit", PrincipalID: "office-intake:i", SessionID: "channel-message:1", IntegrationActor: valid, AuthorityResourceRevision: "p"},
		{Kind: "integration_actor", Issuer: "channel-integration:unit", PrincipalID: "associate:person-1", SessionID: "channel-message:1", IntegrationActor: &withAssociate, AuthorityResourceRevision: "p"},
		{Kind: "integration_actor", Issuer: "channel-integration:unit", PrincipalID: "office-intake:i", SessionID: "other:1", IntegrationActor: valid, AuthorityResourceRevision: "p"},
		{Kind: "integration_actor", Issuer: "unit-person-issuer", PrincipalID: "office-intake:i", SessionID: "channel-message:1", IntegrationActor: valid, AuthorityResourceRevision: "p"},
		{Kind: "integration_actor", Issuer: "channel-integration:unit", PrincipalID: "office-intake:i", SessionID: "channel-message:1", IntegrationActor: &badPhone, AuthorityResourceRevision: "p"},
		{Kind: "integration_actor", Issuer: "channel-integration:unit", PrincipalID: "office-intake:i", SessionID: "channel-message:1"},
		{Kind: "service", Issuer: "unit-person-issuer", PrincipalID: "user-1", SessionID: "s"},
		{Kind: "", Issuer: "unit-person-issuer", PrincipalID: "user-1", SessionID: "s"},
	}
	admitted := 0
	for index, actor := range actors {
		oracle := legacyValidDomainActorKind(plain, actor)
		if oracle {
			admitted++
		}
		if configured.validDomainActorKind(actor) != oracle || plain.validDomainActorKind(actor) != oracle {
			t.Fatalf("actor %d changed from the oracle's %v", index, oracle)
		}
	}
	if admitted != 3 {
		t.Fatalf("the table admits %d, expected 3", admitted)
	}
	if legacyValidDomainActorKind(plain, wlValidActor()) || plain.validDomainActorKind(wlValidActor()) {
		t.Fatal("with no policy a workload stays refused as it always was")
	}
}
