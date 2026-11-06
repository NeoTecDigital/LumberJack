// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDomainLeaseOnlyBeginCurrentACLAndActualPair(t *testing.T) {
	f := domainTestConfigured(t)
	request := domainTestInput(t, f, "command", "one")
	begin := domainTestBegin(t, f, request)
	raw, _ := json.Marshal(begin)
	if strings.Contains(string(raw), `"body"`) || strings.Contains(string(raw), "original") {
		t.Fatal("begin leaked native response before adoption")
	}
	if _, err := f.server.DomainControl(context.Background(), domainTestControl(f, begin, "receive")); err == nil {
		t.Fatal("unadopted result bytes were released")
	}
	received := domainTestReceive(t, f, begin)
	if received.Pair == nil || received.Pair.Sequence == 0 || received.Pair.ReceiptHash == "" || received.Pair.RequestFingerprint != stagedHash(request.Body) {
		t.Fatal("success lacks actual matched native pair")
	}
	stored := stagedTestRecord(t, stagedTestDisk(t, f.server))
	if stored.Metadata["unknown"].(map[string]interface{})["large"] != json.Number("9007199254740993") {
		t.Fatal("native opaque fields lost during real staged publication")
	}
	record := stagedTestRecord(t, f.server.forest)
	f.server.forestMutex.Lock()
	record.Metadata["ownerAcl"] = map[string]interface{}{"contractRevision": "lj.domain.acl/1", "principals": map[string]interface{}{}}
	f.server.forestMutex.Unlock()
	intent, err := f.server.DomainResolve(context.Background(), request.DomainInput)
	if err != nil {
		t.Fatal(err)
	}
	validate := domainTestControl(f, begin, "validate")
	validate.LeaseBinding = &begin.Lease
	validate.Intent = &intent
	validate.PrincipalID = begin.Lease.PrincipalID
	validate.SessionID = begin.Lease.SessionID
	validate.ValidUntil = domainNow() + 5
	if _, err = f.server.DomainControl(context.Background(), validate); err == nil {
		t.Fatal("stale field authority passed current native validation")
	}
	handoff := domainTestControl(f, begin, "handoff")
	handoff.Proof = "handoff-denied"
	if _, err = f.server.DomainControl(context.Background(), handoff); err == nil {
		t.Fatal("account proof bypassed current resource/field ACL")
	}
}
func TestDomainHandoffPermitAndExactCompletion(t *testing.T) {
	f := domainTestConfigured(t)
	begin := domainTestBegin(t, f, domainTestInput(t, f, "command", "two"))
	received := domainTestReceive(t, f, begin)
	handoff := domainTestControl(f, begin, "handoff")
	handoff.Proof = "handoff-two"
	result, err := f.server.DomainControl(context.Background(), handoff)
	if err != nil {
		t.Fatal(err)
	}
	permit := result.Value.(DomainPermit)
	finish := domainTestControl(f, begin, "finish")
	finish.ResponseHash = received.ResponseHash
	finish.Disposition = "handed-off"
	finish.PermitID = "wrong"
	if _, err = f.server.DomainControl(context.Background(), finish); err == nil {
		t.Fatal("wrong handoff permit finished drain obligation")
	}
	finish.PermitID = permit.PermitID
	result, err = f.server.DomainControl(context.Background(), finish)
	if err != nil || !result.Completed {
		t.Fatal("real authorized handoff completion refused", err)
	}
	result, err = f.server.DomainControl(context.Background(), finish)
	if err != nil || !result.Completed {
		t.Fatal("lost completion acknowledgment cannot be retried")
	}
}
func TestDomainUnknownDiscardCannotCompleteUntilRealReconciliation(t *testing.T) {
	f := domainTestConfigured(t)
	publish := f.server.stateWriter.write
	f.server.stateWriter.write = func(stateSnapshot) error { return errors.New("synthetic disk failure") }
	begin := domainTestBegin(t, f, domainTestInput(t, f, "command", "unknown"))
	received := domainTestReceive(t, f, begin)
	if received.Pair != nil || !strings.Contains(string(received.Body), `"status":"unknown"`) {
		t.Fatal("unconfirmed engine mutation claimed a durable pair")
	}
	finish := domainTestControl(f, begin, "finish")
	finish.ResponseHash = received.ResponseHash
	finish.Disposition = "irrevocably-discarded"
	result, err := f.server.DomainControl(context.Background(), finish)
	if err != nil || result.Completed {
		t.Fatal("unknown persistence prematurely finished lease")
	}
	f.server.stateWriter.write = publish
	result, err = f.server.DomainControl(context.Background(), finish)
	if err != nil || !result.Completed {
		t.Fatal("actual paired housekeeping failed to resolve obligation", err)
	}
	stored := stagedTestRecord(t, stagedTestDisk(t, f.server))
	refs := stored.Metadata["roleIds"].([]interface{})
	if len(refs) != 1 || refs[0] != "role-a" {
		t.Fatal("reconciled native effect missing")
	}
}
func TestDomainOwnerCloseWaitsForAdoptedResponseAndDeniesNewAdmission(t *testing.T) {
	f := domainTestConfigured(t)
	begin := domainTestBegin(t, f, domainTestInput(t, f, "read", "close"))
	_ = domainTestReceive(t, f, begin)
	close := domainTestControl(f, begin, "close")
	close.Keys = []DomainGateKey{{begin.Lease.PrincipalID, begin.Lease.SessionID, begin.Lease.Scope}}
	if _, err := f.server.DomainControl(context.Background(), close); err == nil {
		t.Fatal("host handoff channel acquired authority-owner close rights")
	}
	close.ChannelToken = f.config.OwnerControlToken
	result, err := f.server.DomainControl(context.Background(), close)
	if err != nil || result.Value.(map[string]bool)["drained"] {
		t.Fatal("adopted body was counted as discarded", err)
	}
	if _, err = f.server.DomainCall(context.Background(), domainTestInput(t, f, "read", "closed")); err == nil {
		t.Fatal("closed gate admitted another human operation")
	}
	handoff := domainTestControl(f, begin, "handoff")
	handoff.Proof = "handoff-after-close"
	if _, err = f.server.DomainControl(context.Background(), handoff); err == nil {
		t.Fatal("closed adopted lease received a new handoff permit")
	}
	finish := domainTestControl(f, begin, "finish")
	finish.Disposition = "irrevocably-discarded"
	finish.ResponseHash = begin.ResponseHash
	if result, err = f.server.DomainControl(context.Background(), finish); err != nil || !result.Completed {
		t.Fatal(err)
	}
	result, err = f.server.DomainControl(context.Background(), close)
	if err != nil || !result.Value.(map[string]bool)["drained"] {
		t.Fatal("irrevocably discarded body did not finish drain", err)
	}
}
func TestDomainWrongProofBindingUnconfiguredAndMissingPolicyDeny(t *testing.T) {
	f := domainTestConfigured(t)
	f.mu.Lock()
	f.wrongBinding = true
	f.mu.Unlock()
	if _, err := f.server.DomainCall(context.Background(), domainTestInput(t, f, "read", "wrong")); err == nil {
		t.Fatal("callback proofBinding was not tied to supplied opaque bytes")
	}
	plain := stagedTestServer(t, t.TempDir())
	if _, err := plain.DomainResolve(context.Background(), DomainInput{}); err == nil {
		t.Fatal("unconfigured native admission opened")
	}
	if err := plain.ConfigureDomain(f.config, map[string]DomainProduct{"manifest": domainTestProduct{}}, nil); err == nil {
		t.Fatal("missing mandatory policy accepted")
	}
}
func TestDomainCanonicalUTF8AndStrictEscapes(t *testing.T) {
	value := map[string]interface{}{"z": "<>&\u2028\u2029🙂", "a": "exact\n"}
	raw, err := CanonicalDomainJSON(value)
	expected := []byte("{\"a\":\"exact\\n\",\"z\":\"<>&\u2028\u2029🙂\"}")
	if err != nil || string(raw) != string(expected) {
		t.Fatal("native canonical UTF-8 disagrees with frozen Python encoding")
	}
	for _, bad := range []string{`{"label":"\ud800"}`, `{"label":"\udc00"}`, `{"a":1,"a":2}`} {
		var value interface{}
		if DecodeDomainJSON([]byte(bad), &value) == nil {
			t.Fatal("invalid Unicode/duplicate JSON accepted")
		}
	}
	var decoded interface{}
	if DecodeDomainJSON([]byte(`{"label":"\ud83d\ude42"}`), &decoded) != nil {
		t.Fatal("valid surrogate pair rejected")
	}
}
