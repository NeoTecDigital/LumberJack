// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/core"
	"net/http"
	"net/http/httptest"
	"testing"
)

type nativeControlUnit struct {
	f       *sourceUnitFixture
	config  NativeControlConfig
	token   string
	mapping CanonicalResolvedMapping
	deny    bool
	expired bool
}

func nativeUnitBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// Core callback is an explicitly synthetic component boundary, not live Auth/SQL.
func nativeControlUnitNew(t *testing.T) *nativeControlUnit {
	t.Helper()
	t.Setenv("MOMENTUM_REQUIRE_MFA", "false")
	u := &nativeControlUnit{f: sourceUnitFixtureNew(t)}
	callback := httptest.NewServer(http.HandlerFunc(u.callback))
	t.Cleanup(callback.Close)
	f := u.f
	u.config = NativeControlConfig{NativeCanonicalRevision, f.p.epoch, f.config.HostID, f.config.SourceAuthorityRef, f.config.SourcePolicyRevision, nativeControlJWT{nativeUnitBytes(t, 32), nativeUnitBytes(t, 32), nativeUnitBytes(t, 32), 30}, nativeSealConfig{"Ed25519", "unit-seal-key", nativeUnitBytes(t, 32)}, SourceCoreCallback{"unit-map-audience", f.config.CoreCallback.Issuer, callback.URL + "/mapping", fmt.Sprintf("%x", nativeUnitBytes(t, 32))}}
	raw, _ := CanonicalDomainJSON(u.config)
	if _, err := f.server.ConfigureNativeControl(raw); err != nil {
		t.Fatal(err)
	}
	nativeUnitRoot(t, u, "native-home")
	token, _, err := f.server.mintApplicationSession("native-owner")
	if err != nil {
		t.Fatal(err)
	}
	u.token = token
	return u
}
func nativeUnitRoot(t *testing.T, u *nativeControlUnit, id string) {
	t.Helper()
	s := u.f.server
	s.forest.Users = []core.User{{ID: "native-owner", Permissions: []core.Permission{core.AdminPermission}}}
	s.forest.Children[id] = &core.Node{ID: id, Name: id, Kind: "workspace", CreatedBy: "native-owner", Parents: map[string]string{s.forest.ID: s.forest.Name}, Children: map[string]*core.Node{}, Metadata: map[string]interface{}{"personal_owner": "native-owner", "source_unknown": stagedTestUnknown()}, Users: []core.User{{ID: "native-owner", Permissions: []core.Permission{core.AdminPermission}}}, CommandReceipts: map[string]interface{}{}}
}
func nativeUnitRequest(u *nativeControlUnit, action string, payload interface{}) SourceEnvelope {
	r := sourceUnitRequest(u.f, action, payload)
	r.ContractRevision = NativeCanonicalRevision
	return r
}
func nativeUnitCapture(t *testing.T, u *nativeControlUnit, root *string) SourceControlRef {
	t.Helper()
	got, err := u.f.p.captureNativeControl(nativeUnitRequest(u, "control.capture", nativeControlCapture{u.token, root}))
	if err != nil {
		t.Fatal(err)
	}
	return got.(SourceControlRef)
}
func nativeUnitPolicy(u *nativeControlUnit) nativeVerifyPolicy {
	runtime := u.f.server.nativeControl.Load()
	return nativeVerifyPolicy{NativeCanonicalRevision, u.f.p.nativeSourceIdentity(), runtime.config.Seal.KeyID, runtime.publicKey, u.f.config.Bounds}
}
func nativeUnitVerify(u *nativeControlUnit, snapshot interface{}, expected nativeVerifyExpected) error {
	raw, _ := CanonicalDomainJSON(snapshot)
	input, _ := CanonicalDomainJSON(nativeVerifyInput{nativeUnitPolicy(u), raw, expected})
	_, err := VerifyNativeSourceSeal(input)
	return err
}
func TestNativeControlConfigurationStrictAndProtected(t *testing.T) {
	u := nativeControlUnitNew(t)
	cfg := u.config
	raw, _ := CanonicalDomainJSON(cfg)
	if _, err := u.f.server.ConfigureNativeControl(raw); err == nil {
		t.Fatal("reconfiguration accepted")
	}
	cfg.JWT.SessionKey = cfg.Seal.PrivateKey
	raw, _ = CanonicalDomainJSON(cfg)
	if validateNativeConfigBytes(raw, cfg) == nil {
		t.Fatal("JWT key reused for signing")
	}
	cfg = u.config
	cfg.JWT.ExpiresInSeconds = 0
	raw, _ = CanonicalDomainJSON(cfg)
	if validateNativeConfigBytes(raw, cfg) == nil {
		t.Fatal("missing finite duration accepted")
	}
	if fmt.Sprint(cfg) != "NativeControlConfig{private}" {
		t.Fatal("configuration exposed")
	}
	changed := append(raw[:len(raw)-1], []byte(`,"extra":true}`)...)
	if _, err := u.f.server.ConfigureNativeControl(changed); err == nil {
		t.Fatal("unknown setup field accepted")
	}
}
func TestNativeControlEpochAndUniqueRootSelection(t *testing.T) {
	u := nativeControlUnitNew(t)
	if canonicalNativeEpoch("00") || canonicalNativeEpoch("-1") || !canonicalNativeEpoch("0") {
		t.Fatal("epoch normalization changed")
	}
	nativeUnitRoot(t, u, "native-other")
	if _, err := u.f.p.captureNativeControl(nativeUnitRequest(u, "control.capture", nativeControlCapture{u.token, nil})); err == nil {
		t.Fatal("ambiguous home guessed")
	}
	root := "native-other"
	ref := nativeUnitCapture(t, u, &root)
	e, err := u.f.p.capturedControl(ref.ControlRef)
	if err != nil {
		t.Fatal(err)
	}
	u.f.server.forest.Users[0].CredentialEpoch++
	if u.f.p.currentCanonicalControl(e) == nil {
		t.Fatal("captured profile facts ignored")
	}
}
func TestNativeControlClosedWirePreservesOriginalPayload(t *testing.T) {
	u := nativeControlUnitNew(t)
	r := nativeUnitRequest(u, "control.capture", nativeControlCapture{u.token, nil})
	raw, _ := CanonicalDomainJSON(r)
	var decoded SourceEnvelope
	if sourceDecode(raw, &decoded, u.f.config.Bounds) != nil || string(decoded.Payload) != string(r.Payload) {
		t.Fatal("payload bytes altered")
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "requestId")
	raw, _ = CanonicalDomainJSON(fields)
	if sourceDecode(raw, &decoded, u.f.config.Bounds) == nil {
		t.Fatal("missing field accepted")
	}
}
