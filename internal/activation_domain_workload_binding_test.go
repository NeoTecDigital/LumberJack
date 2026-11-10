// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBoundWorkloadStrictIntegerExpiryAndFence(t *testing.T) {
	g := wbGrant(wlAccount, "accounting.sync")
	raw, _ := CanonicalDomainJSON(g)
	var shape map[string]json.RawMessage
	_ = DecodeDomainJSON(raw, &shape)
	for _, value := range []string{"0", "-1", "true", "null", `"1"`, "1.0", "1e3", "9007199254740992"} {
		shape["expiresAt"] = json.RawMessage(value)
		changed, _ := json.Marshal(shape)
		var decoded DomainWorkloadGrant
		if DecodeDomainJSON(changed, &decoded) == nil {
			t.Fatalf("expiry token %s accepted", value)
		}
	}
	w := DomainWorkloadRun{domainWorkloadRunRevision, g, "labelled-run", "18446744073709551615"}
	if validateWorkloadRun(w) != nil {
		t.Fatal("maximum current fence must remain usable")
	}
	for _, fence := range []string{"", "0", "01", "+1", "-1", " 1", "1.0", "1e2", "１", "18446744073709551616", "184467440737095516150"} {
		w.FenceGeneration = fence
		if validateWorkloadRun(w) == nil {
			t.Fatalf("fence %q accepted", fence)
		}
	}
	w.FenceGeneration = "1"
	encoded, _ := CanonicalDomainJSON(w)
	encoded = []byte(strings.Replace(string(encoded), `"fenceGeneration":"1"`, `"fenceGeneration":1`, 1))
	if DecodeDomainJSON(encoded, &w) == nil {
		t.Fatal("numeric fence accepted")
	}
}

func TestBoundWorkloadPolicyUsesExactOwnerCeilings(t *testing.T) {
	config := wbConfig(t)
	if err := validateDomainWorkloadPolicy(config); err != nil {
		t.Fatal("positive complete policy", err)
	}
	for _, damage := range []string{"digest", "purpose", "kind", "field", "owner", "carrier", "lifetime", "legacy-accounting"} {
		wbPolicyDenial(t, damage)
	}
}

func wbPolicyDenial(t *testing.T, damage string) {
	t.Helper()
	config := wbConfig(t)
	policy := config.WorkloadPolicy
	purpose := policy.Purposes["accounting.sync"]
	rule := purpose.Families["business:associate"]
	switch damage {
	case "digest":
		purpose.PolicyDigest = strings.Repeat("0", 64)
	case "purpose":
		policy.Purposes["other.sync"] = purpose
	case "kind":
		rule.Kind = "png_record"
	case "field":
		rule.CreateFields = []string{"account_id", "id", "user_id"}
	case "owner":
		config.ProvisioningProfile.OwnerGrants["root"][nativeStoreCommand] = domainGrant{Fields: []string{"id"}, CreateKinds: []string{"associate", "png_record"}}
	case "carrier":
		config.ProvisioningProfile.Layout.AssociateCarrier = nil
	case "lifetime":
		policy.MaxLifetimeSeconds = 31
	case "legacy-accounting":
		policy.LegacyMessaging = map[string][]string{"business:job": {"id", "account_id"}}
	}
	purpose.Families["business:associate"] = rule
	if damage != "digest" {
		purpose.PolicyDigest, _ = workloadPolicyDigest(policy, "accounting.sync", purpose)
	}
	policy.Purposes["accounting.sync"] = purpose
	if validateDomainWorkloadPolicy(config) == nil {
		t.Fatalf("%s configuration accepted", damage)
	}
}

func TestBoundWorkloadEnrollmentExactGReplayAndRevokeAfterRestart(t *testing.T) {
	f := newBoundWorkloadFixture(t)
	root := aclFixtureProvision(t, f, wlAccount)
	g := wbGrant(wlAccount, "accounting.sync")
	grant := wbInput(t, f, root, g, EnrollmentWorkloadGrant, "grant")
	first := f.enroll(t, grant)
	enrollmentAssertAppliedPair(t, f.received(t, first), first, "applied")
	coownerFinish(t, f, first, "labelled_grant_handoff")
	wbAssertInstalled(t, f, root, g)
	aclFixtureRestart(t, f)
	wbAssertInstalled(t, f, root, g)
	revoke := wbInput(t, f, root, g, EnrollmentWorkloadRevoke, "revoke")
	removed := f.enroll(t, revoke)
	enrollmentAssertAppliedPair(t, f.received(t, removed), removed, "applied")
	coownerFinish(t, f, removed, "labelled_revoke_handoff")
	g.GrantRevision = "labelled-G2"
	f.mu.Lock()
	f.targetRevision = g.GrantRevision
	f.mu.Unlock()
	next := f.enroll(t, wbInput(t, f, root, g, EnrollmentWorkloadGrant, "regrant"))
	f.received(t, next)
	coownerFinish(t, f, next, "labelled_regrant_handoff")
	revoke.Proof = "labelled_old_revoke_replay"
	f.mu.Lock()
	f.targetState = "revoked"
	f.mu.Unlock()
	if _, err := f.server.DomainEnroll(contextBackground(), revoke); err == nil {
		t.Fatal("old revoke replayed as current over successor G")
	}
	wbAssertInstalled(t, f, root, g)
}

func wbAssertInstalled(t *testing.T, f *enrollmentFixture, root string, g DomainWorkloadGrant) {
	t.Helper()
	acl := wlRootACL(t, f, root)
	target := workloadPrincipal(g)
	if acl.ContractRevision != domainCoownerACLRevision || !domainEqual(acl.Principals[target][nativeStoreCommand].WorkloadGrant, &g) {
		t.Fatal("exact G missing on actual root")
	}
	for _, kind := range []string{"png_record", "associate"} {
		if !domainEqual(acl.CreateACLs[kind].Principals[target][nativeStoreCommand].WorkloadGrant, &g) {
			t.Fatal("exact G missing on actual template", kind)
		}
	}
	if !domainEqual(acl.Principals[aclFixtureOwner], f.config.ProvisioningProfile.OwnerGrants["root"]) {
		t.Fatal("founder provenance/grants changed")
	}
}

func TestBoundWorkloadRequestAndVerifiedGrammarsStaySeparate(t *testing.T) {
	f := newBoundWorkloadFixture(t)
	root := aclFixtureProvision(t, f, wlAccount)
	input := wbInput(t, f, root, wbGrant(wlAccount, "messaging.sync"), EnrollmentWorkloadGrant, "shape")
	raw, err := CanonicalDomainJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"administration":null`) {
		t.Fatal("required null administration omitted")
	}
	if _, err = DecodeEnrollmentInput(raw, 100000); err != nil {
		t.Fatal(err)
	}
	for _, old := range []string{EnrollmentRevision, EnrollmentAdminRevision, EnrollmentCoownerRevision} {
		changed := input
		changed.Request.ContractRevision = old
		if _, err := canonicalEnrollmentRequest(changed.Request, 100000); err == nil {
			t.Fatal("G entered older grammar", old)
		}
	}
	actor := f.actor(EnrollmentCheck{Request: input.Request})
	actor.ContractRevision = EnrollmentBoundWorkloadProofRevision
	answer, _ := CanonicalDomainJSON(actor)
	if _, err = decodeEnrollmentVerified(answer); err == nil {
		t.Fatal("missing explicit administratorAuthorized accepted")
	}
}

func wbRecordEntry() *domainEntry {
	g := wbGrant(wlAccount, "messaging.sync")
	w := &DomainWorkloadRun{domainWorkloadRunRevision, g, "labelled-run", "1"}
	operation := nativeStoreCommand
	intent := DomainIntent{ContractRevision: domainStoreContract, Scope: DomainScope{wlAccount, "manifest"}, Mode: "command", Operation: &operation, RequestFingerprint: stagedHash([]byte("labelled-product-body")), Workload: w}
	return &domainEntry{actor: DomainVerified{Kind: domainWorkloadKind, PrincipalID: workloadPrincipal(g), SessionID: workloadSession(*w), Workload: w}, intent: intent, input: DomainInput{Mode: "command"}, owned: DomainOwnedScope{Bounds: stagedTestBounds()}}
}

func TestBoundWorkloadRetainedRunAndZeroTargetReplayCannotBeAdopted(t *testing.T) {
	entry := wbRecordEntry()
	raw, err := workloadRecordFor(entry)
	if err != nil {
		t.Fatal(err)
	}
	receipt := stagedReceipt{Command: stagedCommand{PrincipalID: entry.actor.PrincipalID, Action: nativeStoreCommand}, WorkloadRecord: raw, Targets: []stagedTarget{}}
	calls := 0
	authorize := func(access stagedAccess) error { calls++; return authorizeWorkloadReplay(entry, access) }
	if err := authorizeStagedReplay(authorize, stagedBinding{}, receipt); err != nil || calls != 1 {
		t.Fatal("zero-target replay did not check actual W", err, calls)
	}
	for _, change := range []string{"run", "fence", "grant", "connection", "purpose", "missing"} {
		wbReplayDenial(t, raw, change)
	}
}

func wbReplayDenial(t *testing.T, raw []byte, change string) {
	t.Helper()
	entry := wbRecordEntry()
	switch change {
	case "run":
		entry.actor.Workload.RunID = "another-run"
	case "fence":
		entry.actor.Workload.FenceGeneration = "2"
	case "grant":
		entry.actor.Workload.Grant.GrantRevision = "labelled-G2"
	case "connection":
		entry.actor.Workload.Grant.ConnectionID = "another-connection"
	case "purpose":
		entry.actor.Workload.Grant.Purpose = "accounting.sync"
	case "missing":
		raw = nil
	}
	receipt := stagedReceipt{Command: stagedCommand{PrincipalID: entry.actor.PrincipalID, Action: nativeStoreCommand}, WorkloadRecord: raw, Targets: []stagedTarget{}}
	authorize := func(access stagedAccess) error { return authorizeWorkloadReplay(entry, access) }
	if authorizeStagedReplay(authorize, stagedBinding{}, receipt) == nil {
		t.Fatalf("%s retained command adopted", change)
	}
}

func TestBoundWorkloadReceiptHashCoversRunAndRejectsMixedMembers(t *testing.T) {
	entry := wbRecordEntry()
	record, err := workloadRecordFor(entry)
	if err != nil {
		t.Fatal(err)
	}
	binding := stagedTestBinding()
	binding.ProductID, binding.AccountID = "manifest", wlAccount
	command := stagedCommand{PrincipalID: entry.actor.PrincipalID, AccountID: wlAccount, ScopeID: binding.ScopeID, CommandID: "labelled-command", Action: nativeStoreCommand, BodySHA256: entry.intent.RequestFingerprint, ExpectedRevision: "labelled-before"}
	receipt := stagedReceipt{Version: 1, Command: command, Fingerprint: stagedCommandFingerprint(binding, command), AfterRevision: "labelled-after", Targets: []stagedTarget{{NodeID: "labelled-native", Kind: "png_record", Fields: []string{"pngData"}}}, WorkloadRecord: record}
	result := nativeStoreProductResult{Records: []nativeStoreReceiptRecord{{Family: wlMessages, Key: "labelled-row", NativeID: "labelled-native", Version: stagedHash([]byte("labelled-version")), Data: map[string]interface{}{"id": "labelled-row", "account_id": wlAccount}}}, Result: json.RawMessage("null")}
	receipt.ProductIntent = wbJSON(t, result)
	first, err := stagedReceiptPair(binding, stagedCommandKey(command), wbJSON(t, receipt))
	if err != nil {
		t.Fatal(err)
	}
	entry.actor.Workload.FenceGeneration = "2"
	receipt.WorkloadRecord, _ = workloadRecordFor(entry)
	second, err := stagedReceiptPair(binding, stagedCommandKey(command), wbJSON(t, receipt))
	if err != nil || first.ReceiptHash == second.ReceiptHash {
		t.Fatal("W not covered by actual canonical receipt hash", err)
	}
	receipt.EnrollmentRecord = []byte(`{}`)
	var decoded stagedReceipt
	if decodeStagedProductReceipt(wbJSON(t, receipt), &decoded, 100000) == nil {
		t.Fatal("mixed enrollment/workload accepted")
	}
}

func wbJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := CanonicalDomainJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
