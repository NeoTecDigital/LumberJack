// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEnrollmentAssociateCarrierOmittedPreservesLegacyProfile(t *testing.T) {
	config := enrollmentFixtureConfig(t)
	if err := validateDomainProvisioningProfile(config); err != nil {
		t.Fatal("omitted carrier changed existing protected enrollment", err)
	}
	raw, err := CanonicalDomainJSON(config.ProvisioningProfile)
	if err != nil || bytes.Contains(raw, []byte(`"associateCarrier"`)) {
		t.Fatal("absent carrier was serialized as an opt-in", err)
	}
	var decoded DomainProvisioningProfile
	if err := DecodeDomainJSON(raw, &decoded); err != nil || decoded.Layout.AssociateCarrier != nil {
		t.Fatal("omitted carrier did not round-trip unchanged", err)
	}
}

func TestEnrollmentAssociateCarrierStrictProfileRoundTripAndDigest(t *testing.T) {
	config := enrollmentCarrierConfig(t)
	if err := validateDomainProvisioningProfile(config); err != nil {
		t.Fatal("explicit valid Associate carrier rejected", err)
	}
	raw, err := CanonicalDomainJSON(config.ProvisioningProfile)
	var decoded DomainProvisioningProfile
	if err != nil || DecodeDomainJSON(raw, &decoded) != nil || decoded.Layout.AssociateCarrier == nil {
		t.Fatal("protected carrier could not pass actual profile decoding", err)
	}
	config.ProvisioningProfile = &decoded
	if err := validateDomainProvisioningProfile(config); err != nil {
		t.Fatal("carrier digest changed in wire round-trip", err)
	}
	label := "LABELLED changed null label"
	decoded.Layout.AssociateCarrier.NullLabel = &label
	if validateDomainProvisioningProfile(config) == nil {
		t.Fatal("carrier policy was excluded from protected exact profile digest")
	}
}

func TestEnrollmentAssociateCarrierRejectsMissingUnknownOrNullPolicyWire(t *testing.T) {
	for _, damage := range []string{"policy-null", "contractRevision", "family", "nativeKind", "labelField", "nullLabel", "initialRoleIds", "unknown", "null-label", "null-roles", "nonempty-roles", "wrong-type"} {
		t.Run(damage, func(t *testing.T) { enrollmentCarrierRejectWire(t, damage) })
	}
}

func enrollmentCarrierRejectWire(t *testing.T, damage string) {
	t.Helper()
	config := enrollmentCarrierConfig(t)
	raw, _ := CanonicalDomainJSON(config.ProvisioningProfile)
	var profile map[string]interface{}
	if err := DecodeDomainJSON(raw, &profile); err != nil {
		t.Fatal(err)
	}
	layout := profile["layout"].(map[string]interface{})
	carrier := layout["associateCarrier"].(map[string]interface{})
	switch damage {
	case "policy-null":
		layout["associateCarrier"] = nil
	case "unknown":
		carrier["implicitRoleGrant"] = true
	case "null-label":
		carrier["nullLabel"] = nil
	case "null-roles":
		carrier["initialRoleIds"] = nil
	case "nonempty-roles":
		carrier["initialRoleIds"] = []string{"LABELLED-role"}
	case "wrong-type":
		carrier["nullLabel"] = json.Number("3")
	default:
		delete(carrier, damage)
	}
	raw, _ = CanonicalDomainJSON(profile)
	var decoded DomainProvisioningProfile
	if DecodeDomainJSON(raw, &decoded) == nil {
		t.Fatal("incomplete/null/unknown carrier encoding silently accepted or omitted")
	}
}

func TestEnrollmentAssociateCarrierRejectsUnsupportedPolicyAndNilRoles(t *testing.T) {
	cases := []func(*DomainAssociateCarrierPolicy){
		func(p *DomainAssociateCarrierPolicy) { p.ContractRevision = "manifest-associate-carrier/0.2" },
		func(p *DomainAssociateCarrierPolicy) { p.Family = "business:job" },
		func(p *DomainAssociateCarrierPolicy) { p.NativeKind = "png_record" },
		func(p *DomainAssociateCarrierPolicy) { p.LabelField = "email" },
		func(p *DomainAssociateCarrierPolicy) { p.NullLabel = nil },
		func(p *DomainAssociateCarrierPolicy) { value := string([]byte{0xff}); p.NullLabel = &value },
		func(p *DomainAssociateCarrierPolicy) { p.InitialRoleIDs = nil },
		func(p *DomainAssociateCarrierPolicy) { p.InitialRoleIDs = []string{"LABELLED-role"} },
	}
	for index, damage := range cases {
		config := enrollmentCarrierConfig(t)
		damage(config.ProvisioningProfile.Layout.AssociateCarrier)
		if validateEnrollmentAssociateCarrier(*config.ProvisioningProfile, config) == nil {
			t.Fatalf("invalid protected policy %d bypassed explicit carrier requirements", index)
		}
	}
}

func TestEnrollmentAssociateCarrierCannotBypassMappingsProfilesOrCreateTemplates(t *testing.T) {
	cases := []func(*DomainProvisioningProfile, *DomainConfig){
		func(p *DomainProvisioningProfile, _ *DomainConfig) { delete(p.Layout.Kinds, "associate") },
		func(p *DomainProvisioningProfile, _ *DomainConfig) { delete(p.Layout.Kinds, "png_record") },
		func(p *DomainProvisioningProfile, _ *DomainConfig) {
			p.Layout.Kinds["associate"] = p.Layout.Kinds["png_record"]
		},
		func(p *DomainProvisioningProfile, _ *DomainConfig) {
			p.Layout.Kinds["associate"] = p.Layout.Kinds["root"]
		},
		func(p *DomainProvisioningProfile, _ *DomainConfig) { delete(p.Layout.Fields, "pngData") },
		func(p *DomainProvisioningProfile, _ *DomainConfig) {
			p.Layout.Fields["pngKey"] = p.Layout.Fields["label"]
		},
		func(p *DomainProvisioningProfile, c *DomainConfig) { p.Layout.Fields["pngFamily"] = c.ACLMetadataKey },
		func(p *DomainProvisioningProfile, _ *DomainConfig) {
			delete(p.Layout.Profiles["png.store.read"], "associate")
		},
		func(p *DomainProvisioningProfile, _ *DomainConfig) {
			delete(p.Layout.Profiles["png.store.write.define"], "associate")
		},
		func(p *DomainProvisioningProfile, _ *DomainConfig) {
			delete(p.OwnerGrants["associate"], "png.store.write.define")
		},
		func(p *DomainProvisioningProfile, _ *DomainConfig) {
			delete(p.OwnerGrants["root"], "png.store.write.define")
		},
		func(p *DomainProvisioningProfile, _ *DomainConfig) { delete(p.Layout.Routes, "png.store.read") },
		func(p *DomainProvisioningProfile, _ *DomainConfig) {
			p.Layout.Routes["png.store.write.define"] = DomainRoute{Method: "GET", Target: "/LABELLED/store"}
		},
	}
	for index, damage := range cases {
		config := enrollmentCarrierConfig(t)
		damage(config.ProvisioningProfile, &config)
		enrollmentCarrierPin(t, config.ProvisioningProfile)
		if validateDomainProvisioningProfile(config) == nil {
			t.Fatalf("incomplete carrier mappings/profile/template %d accepted", index)
		}
	}
}

func TestEnrollmentAssociateCarrierCannotFallbackToGenericCreateAuthority(t *testing.T) {
	config := enrollmentCarrierConfig(t)
	profile := config.ProvisioningProfile
	grant := profile.OwnerGrants["root"]["png.store.write.define"]
	grant.CreateKinds = []string{"png_record"}
	profile.OwnerGrants["root"]["png.store.write.define"] = grant
	enrollmentCarrierPin(t, profile)
	if validateDomainProvisioningProfile(config) == nil {
		t.Fatal("generic png_record creation was reused as Associate authority")
	}
}

func TestEnrollmentAssociateCarrierRequiresSeparatePNGAndGraphFieldCeilings(t *testing.T) {
	for _, field := range []string{"id", "pngKey", "pngFamily", "pngData", "pngVersion", "accountId", "label", "roleIds"} {
		config := enrollmentCarrierConfig(t)
		p := config.ProvisioningProfile
		fields := enrollmentCarrierWithout(p.Layout.Profiles["png.store.write.define"]["associate"], field)
		p.Layout.Profiles["png.store.write.define"]["associate"] = fields
		p.OwnerGrants["associate"]["png.store.write.define"] = domainGrant{Fields: fields, Reference: true}
		enrollmentCarrierPin(t, p)
		if validateDomainProvisioningProfile(config) == nil {
			t.Fatalf("missing Associate field %s was accepted", field)
		}
	}
}

func TestEnrollmentAssociateCarrierRequiresRootProjectionAndExactOwnerTemplate(t *testing.T) {
	for _, kind := range []string{"root", "associate"} {
		config := enrollmentCarrierConfig(t)
		p := config.ProvisioningProfile
		fields := enrollmentCarrierWithout(p.Layout.Profiles["png.store.write.define"][kind], "roleIds")
		p.Layout.Profiles["png.store.write.define"][kind] = fields
		grant := p.OwnerGrants[kind]["png.store.write.define"]
		grant.Fields = fields
		p.OwnerGrants[kind]["png.store.write.define"] = grant
		enrollmentCarrierPin(t, p)
		if validateDomainProvisioningProfile(config) == nil {
			t.Fatalf("missing %s projection authority was accepted", kind)
		}
	}
}

func TestEnrollmentAssociateCarrierPreservesEmptyRolesAndActualCreateTemplate(t *testing.T) {
	config := enrollmentCarrierConfig(t)
	p := config.ProvisioningProfile
	acl := enrollmentACL(p, "LABELLED-original-principal", "root")
	if !domainContains(acl.Principals["LABELLED-original-principal"]["png.store.write.define"].CreateKinds, "associate") {
		t.Fatal("actual root ACL did not retain explicit Associate creation authority")
	}
	associate, present := acl.CreateACLs["associate"]
	if !present || !domainEqual(associate.Principals["LABELLED-original-principal"], p.OwnerGrants["associate"]) {
		t.Fatal("Associate creation used no explicit per-kind owner ACL template")
	}
	if p.Layout.AssociateCarrier.InitialRoleIDs == nil || len(p.Layout.AssociateCarrier.InitialRoleIDs) != 0 {
		t.Fatal("carrier policy invented initial business Roles")
	}
}

func enrollmentCarrierConfig(t *testing.T) DomainConfig {
	t.Helper()
	config := enrollmentFixtureConfig(t)
	p := config.ProvisioningProfile
	nullLabel := ""
	p.Layout.AssociateCarrier = &DomainAssociateCarrierPolicy{ContractRevision: "manifest-associate-carrier/0.1", Family: "business:associate", NativeKind: "associate", LabelField: "full_name", NullLabel: &nullLabel, InitialRoleIDs: []string{}}
	p.Layout.Kinds["png_record"] = "LABELLED-native-png-record"
	for _, field := range []string{"pngKey", "pngFamily", "pngData", "pngVersion"} {
		p.Layout.Fields[field] = "LABELLED." + field
	}
	p.Layout.Profiles["read"]["png_record"] = []string{"id", "reference"}
	p.OwnerGrants["png_record"] = map[string]domainGrant{"read": {Fields: []string{"id", "reference"}, Reference: true}}
	for _, operation := range []string{"png.store.read", "png.store.write.define"} {
		p.Layout.Routes[operation] = DomainRoute{Method: "POST", Target: "/LABELLED/store/" + operation}
		p.Layout.Profiles[operation] = map[string][]string{"root": enrollmentCarrierStoreFields(), "png_record": enrollmentCarrierStoreFields(), "associate": enrollmentCarrierStoreFields()}
		enrollmentFixtureOperationGrants(p, operation, p.Layout.Profiles[operation])
	}
	grant := p.OwnerGrants["root"]["png.store.write.define"]
	grant.CreateKinds = []string{"png_record", "associate"}
	p.OwnerGrants["root"]["png.store.write.define"] = grant
	enrollmentCarrierPin(t, p)
	return config
}

func enrollmentCarrierStoreFields() []string {
	return []string{"id", "pngKey", "pngFamily", "pngData", "pngVersion", "accountId", "label", "roleIds", "reference", "family.business:associate", "data.id", "data.account_id", "data.full_name"}
}

func enrollmentCarrierPin(t *testing.T, profile *DomainProvisioningProfile) {
	t.Helper()
	digest, err := DomainProvisioningProfileDigest(*profile)
	if err != nil {
		t.Fatal(err)
	}
	profile.ProfileRef.ProfileDigest = digest
}

func enrollmentCarrierWithout(fields []string, missing string) []string {
	result := []string{}
	for _, field := range fields {
		if field != missing {
			result = append(result, field)
		}
	}
	return result
}
