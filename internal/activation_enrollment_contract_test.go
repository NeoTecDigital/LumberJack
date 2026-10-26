// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"testing"
)

func TestEnrollmentCanonicalRequestMatchesPythonUTF8Vector(t *testing.T) {
	request := EnrollmentRequest{ContractRevision: EnrollmentRevision, Scope: DomainScope{AccountID: "acct-α", Product: "manifest"}, CommandID: "cmd-α", ExpectedRevision: "absent", Operation: EnrollmentProvision, ProfileRef: EnrollmentProfileRef{ProfileID: "profile-unit", ProfileRevision: "rev-2", ProfileDigest: stagedHash(nil)}}
	raw, err := CanonicalEnrollmentRequest(request, 2000)
	if err != nil || stagedHash(raw) != "99bbdbb083005ca9829266f8fd849ca5085225c370037cc0e6ddeb0addbda6ff" {
		t.Fatal("Go/Python canonical UTF-8 request digest diverged", err)
	}
}

func TestEnrollmentRequestRejectsAbsentNullUnknownAndDuplicateFields(t *testing.T) {
	for _, damage := range []string{"absent-target", "extra-email", "null-account", "legacy-revision", "unknown-operation", "duplicate", "unpaired-surrogate", "zero-bound", "oversize"} {
		t.Run(damage, func(t *testing.T) { enrollmentRejectRequestShape(t, damage) })
	}
}

func enrollmentRejectRequestShape(t *testing.T, damage string) {
	t.Helper()
	f := &enrollmentFixture{config: enrollmentFixtureConfig(t)}
	input := f.input(EnrollmentProvision, "unit-shape-account", "unit-command", "unit-proof", "absent", nil)
	raw, _ := CanonicalDomainJSON(input)
	var value map[string]interface{}
	_ = DecodeDomainJSON(raw, &value)
	request := value["request"].(map[string]interface{})
	maximum := f.config.MaxRequestBytes
	enrollmentDamageRequest(value, request, damage)
	raw, _ = CanonicalDomainJSON(value)
	switch damage {
	case "duplicate":
		raw = append([]byte(`{"proof":"unit-another",`), raw[1:]...)
	case "unpaired-surrogate":
		raw = []byte(`{"requestId":"\ud800"}`)
	case "zero-bound":
		maximum = 0
	case "oversize":
		maximum = len(raw) - 1
	}
	if _, err := DecodeEnrollmentInput(raw, maximum); err == nil {
		t.Fatal("invalid/unspecified/absent wire field accepted")
	}
}

func enrollmentDamageRequest(value, request map[string]interface{}, damage string) {
	switch damage {
	case "absent-target":
		delete(request, "targetPrincipalId")
	case "extra-email":
		value["email"] = "not-authority.example"
	case "null-account":
		request["scope"].(map[string]interface{})["accountId"] = nil
	case "legacy-revision":
		request["contractRevision"] = "manifest-account-enrollment/0.1"
	case "unknown-operation":
		request["operation"] = "manifest.scope.admin.promote"
	}
}

func TestEnrollmentProtectedProfileDigestAndNoSilentOptionalRewrite(t *testing.T) {
	for _, damage := range []string{"changed-bound", "false-reference", "null-create", "target-owner-pin", "empty-default-map", "unknown-profile"} {
		t.Run(damage, func(t *testing.T) { enrollmentRejectProfileShape(t, damage) })
	}
}

func enrollmentRejectProfileShape(t *testing.T, damage string) {
	t.Helper()
	config := enrollmentFixtureConfig(t)
	raw, _ := CanonicalDomainJSON(config.ProvisioningProfile)
	var profile map[string]interface{}
	_ = DecodeDomainJSON(raw, &profile)
	grant := profile["ownerGrants"].(map[string]interface{})["root"].(map[string]interface{})[EnrollmentProvision].(map[string]interface{})
	enrollmentDamageProfile(profile, grant, damage)
	raw, _ = CanonicalDomainJSON(profile)
	var decoded DomainProvisioningProfile
	err := DecodeDomainJSON(raw, &decoded)
	if err == nil {
		config.ProvisioningProfile = &decoded
		err = validateDomainProvisioningProfile(config)
	}
	if err == nil {
		t.Fatal("noncanonical/unpinned profile silently accepted or rewritten")
	}
}

func enrollmentDamageProfile(profile, grant map[string]interface{}, damage string) {
	switch damage {
	case "changed-bound":
		profile["bounds"].(map[string]interface{})["maxNodes"] = json.Number("51")
	case "false-reference":
		grant["reference"] = false
	case "null-create":
		grant["createKinds"] = nil
	case "target-owner-pin":
		grant["targetGrantRevision"] = ""
	case "empty-default-map":
		profile["layout"].(map[string]interface{})["applicationCreateDefaults"] = map[string]interface{}{}
	case "unknown-profile":
		profile["implicitOwnerTier"] = "administrator"
	}
}

func TestEnrollmentReceiptRejectsMissingOrMixedProvenance(t *testing.T) {
	f := newEnrollmentFixture(t)
	begin := f.enroll(t, f.input(EnrollmentProvision, "unit-record-account", "unit-record-command", "unit-record-proof", "absent", nil))
	entry := f.server.domain.entries[begin.Lease.LeaseID]
	scope := f.server.stagedScopes[entry.owned.Binding.ScopeID]
	receipt, err := f.server.enrollmentHistoryLocked(scope, entry.receiptKey)
	if err != nil {
		t.Fatal(err)
	}
	missing := receipt
	missing.EnrollmentRecord = nil
	if validateEnrollmentReceipt(scope.descriptor.Binding, missing, scope.descriptor.Bounds.MaxScopeBytes) == nil {
		t.Fatal("enrollment action without real provenance accepted")
	}
	mixed := receipt
	mixed.ProductIntent = []byte(`{}`)
	if validateEnrollmentReceipt(scope.descriptor.Binding, mixed, scope.descriptor.Bounds.MaxScopeBytes) == nil {
		t.Fatal("mixed receipt grammar accepted")
	}
}
