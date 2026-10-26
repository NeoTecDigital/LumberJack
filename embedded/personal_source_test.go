// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"encoding/json"
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"strings"
	"testing"
	"time"
)

func sourceEmbeddedConfig() map[string]interface{} {
	return map[string]interface{}{"contractRevision": "activation-native-personal-source/0.1", "hostId": "unit-host", "sourceAuthorityRef": "unit-source", "sourcePolicyRevision": "unit-policy", "controlToken": strings.Repeat("u", 32), "coreCallback": map[string]interface{}{"issuer": "https://unit.invalid", "audience": "unit-source", "endpoint": "http://127.0.0.1:18086/verify", "channelToken": strings.Repeat("v", 32)}, "bounds": map[string]interface{}{"maxRequestBytes": 1 << 20, "maxResponseBytes": 1 << 20, "maxSources": 32, "maxBindings": 32, "maxContexts": 64, "maxResources": 64, "maxFields": 32, "maxLeases": 32, "maxRetainedEpochs": 64, "leaseSeconds": 30, "requestSeconds": 15}, "stagedBounds": map[string]int{"maxNodes": 50, "maxChanges": 20, "maxReceipts": 30, "maxIdentifierBytes": 200, "maxValueDepth": 20, "maxScopeBytes": 100000, "maxSnapshotBytes": 1000000}}
}
func TestPersonalSourceSameRuntimeConfigureZeroRootsAndClose(t *testing.T) {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	h, err := Open(embeddedConfig(t), "unit-asserted-not-authority")
	if err != nil {
		t.Fatal(err)
	}
	rt := h.runtime
	config := sourceEmbeddedConfig()
	raw, _ := json.Marshal(config)
	output, err := h.ConfigurePersonalSource(raw)
	if err != nil {
		t.Fatal(err)
	}
	var configured struct {
		Configured bool   `json:"configured"`
		Epoch      string `json:"epoch"`
		MaxLeases  int    `json:"maxLeases"`
	}
	if err = engine.DecodeDomainJSON(output, &configured); err != nil || !configured.Configured || configured.Epoch == "" {
		t.Fatal("actual configure witness missing", err)
	}
	payload, _ := json.Marshal(map[string]string{"principalId": "unit-principal", "sessionId": "unit-session"})
	input := engine.SourceEnvelope{ContractRevision: "activation-native-personal-source/0.1", Action: "roots.snapshot", Epoch: configured.Epoch, HostID: "unit-host", ChannelToken: strings.Repeat("u", 32), RequestID: "unit-request", ValidUntil: float64(time.Now().UnixNano())/1e9 + 10, Payload: payload}
	body, _ := json.Marshal(input)
	if _, err = h.PersonalSourceCall(body); err != nil {
		t.Fatal(err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	if inRegistry(rt.path) {
		t.Fatal("zero-entry source prevented real close")
	}
	if _, err = PersonalSourceControlCall(body); err == nil {
		t.Fatal("closed source epoch fabricated runtime")
	}
}
