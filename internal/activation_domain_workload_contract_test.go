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
