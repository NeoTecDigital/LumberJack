// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPersonalSourcePrivateLedgerPersistsButPublicNodeDTOExcludes(t *testing.T) {
	f := sourceUnitFixtureNew(t)
	e, _, _ := sourceUnitCommitted(t, f)
	disk := stagedTestDisk(t, f.server)
	if disk.PersonalBindings.Bindings[f.grant.Account.AccountID].PrincipalID != f.actor.PrincipalID {
		t.Fatal("private canonical binding lost")
	}
	visible := f.server.Forest(e.candidate.OwnerID)
	raw, err := json.Marshal(visible)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"personal_bindings", f.actor.PrincipalID, f.grant.Account.AccountID, f.grant.Account.SubjectRef.SubjectID, "unit-sql-account-1"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private ledger leaked from actual explicit NodeView", private)
		}
	}
	if disk.PersonalBindings.Receipts[personalReceiptKey(f.actor.PrincipalID, f.grant.Account.AccountID, e.candidate.CommandID)].Receipt.CommandSHA256 != e.intent.CommandSHA256 {
		t.Fatal("stable receipt not persisted")
	}
}
func TestPersonalSourceIdentityAbsentRelationCannotBeGuessed(t *testing.T) {
	f := sourceUnitFixtureNew(t)
	input := sourceIdentityOpen{NativeEvidenceRef: "unit-unlinked", Subject: f.actor.Evidence, Purpose: "identity.association.establish"}
	if _, err := f.p.identityOpen(sourceUnitRequest(f, "identity.open", input), false); err == nil {
		t.Fatal("absent relation inferred from subject")
	}
}
