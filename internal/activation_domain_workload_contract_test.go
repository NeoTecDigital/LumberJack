// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"os"
	"regexp"
	"testing"
)

var wlContractBlock = regexp.MustCompile("(?s)```json ([a-z-]+)\n(.*?)```")

func wlContractBlocks(t *testing.T) map[string][]byte {
	t.Helper()
	raw, err := os.ReadFile("../docs/workload-write-grant.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := map[string][]byte{}
	for _, match := range wlContractBlock.FindAllSubmatch(raw, -1) {
		blocks[string(match[1])] = match[2]
	}
	return blocks
}

// The contract is what the sync lane writes against, so what it shows must be what the engine takes.
func TestWorkloadContractExamplesDecode(t *testing.T) {
	blocks := wlContractBlocks(t)
	if len(blocks) != 4 {
		t.Fatalf("contract has %d examples", len(blocks))
	}
	var policy DomainWorkloadPolicy
	if err := DecodeDomainJSON(blocks["policy"], &policy); err != nil {
		t.Fatal(err)
	}
	config := wlFixtureConfig(t)
	config.WorkloadPolicy = &policy
	for family, fields := range policy.Families {
		if !domainWorkloadFamilies[family] {
			t.Fatalf("contract names %s", family)
		}
		if err := validateDomainWorkloadFields(fields, config.MaxFields); err != nil {
			t.Fatal(err)
		}
	}
	var actor DomainVerified
	if err := DecodeDomainJSON(blocks["workload-answer"], &actor); err != nil {
		t.Fatal(err)
	}
	d := wlEngine()
	d.config.WorkloadPolicy = &policy
	if !d.validDomainActorKind(actor) {
		t.Fatalf("the contract's answer is not a valid workload: %+v", actor)
	}
	input, err := DecodeEnrollmentInput(blocks["grant-input"], 100000)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := decodeEnrollmentVerified(blocks["grant-answer"])
	if err != nil {
		t.Fatal(err)
	}
	if !domainEqual(answer.Request, input.Request) || !enrollmentActorAuthorized(answer) || !d.validEnrollmentWorkloadForms(answer) {
		t.Fatal("the contract's grant answer does not fit its grant")
	}
}

// Golden independently encoded UTF-8 tuple; neither custody's ASCII escaping nor
// a floating-point expiry/fence may replace this native canonical commitment.
func TestBoundWorkloadCanonicalTupleAndMaximumExpiry(t *testing.T) {
	g := wbGrant("labelled-account", "accounting.sync")
	g.InstallationID = "LABELLED-安装"
	g.ConnectionID = "labelled-connection"
	g.ExpiresAt = 9007199254740991
	if workloadPrincipal(g) != "workload:ac7be8915dbcd86904fc02b645368634a02222b1c0dddb2039d021a9b27beb69" {
		t.Fatal("native tuple canonical parity changed")
	}
	raw := wbJSON(t, g)
	var decoded DomainWorkloadGrant
	if err := DecodeDomainJSON(raw, &decoded); err != nil || decoded.ExpiresAt != g.ExpiresAt {
		t.Fatal("maximum exact JSON integer lost", err)
	}
	policy := wbPolicy()
	var roundtrip DomainWorkloadPolicy
	if err := DecodeDomainJSON(wbJSON(t, policy), &roundtrip); err != nil || !domainEqual(policy, &roundtrip) {
		t.Fatal("closed policy parity", err)
	}
}
