// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	engine "github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/products/pngstore"
	"testing"
)

type pngFixtureExchange struct {
	begin    engine.DomainBegin
	received engine.DomainReceived
	intent   engine.DomainIntent
	body     map[string]interface{}
}

func pngFixtureInput(t *testing.T, body pngstore.Request, mode string) DomainInput {
	target := "/manifest/native-store/read"
	if mode == "command" {
		target = "/manifest/native-store/execute"
	}
	return DomainInput{Mode: mode, Method: "POST", Target: target, Body: domainFixtureJSON(t, body)}
}
func pngFixtureResolve(t *testing.T, handle *Handle, input DomainInput) engine.DomainIntent {
	t.Helper()
	raw, err := handle.DomainResolve(domainFixtureJSON(t, input))
	var intent engine.DomainIntent
	if err != nil || engine.DecodeDomainJSON(raw, &intent) != nil {
		t.Fatal("actual PNG resolve failed", err)
	}
	return intent
}
func pngFixtureCall(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, body pngstore.Request, mode, principal string) pngFixtureExchange {
	t.Helper()
	input := pngFixtureInput(t, body, mode)
	intent := pngFixtureResolve(t, handle, input)
	token := authority.issue(intent, "admission", nil, principal)
	begin, received := domainFixtureExchange(t, handle, config, DomainRequest{DomainInput: input, RequestID: "png-fixture-request", Proof: token})
	var result map[string]interface{}
	if err := engine.DecodeDomainJSON(received.Body, &result); err != nil {
		t.Fatal(err)
	}
	return pngFixtureExchange{begin, received, intent, result}
}
func pngFixtureFinish(t *testing.T, config DomainConfig, authority *pngFixtureAuthority, exchange pngFixtureExchange, disclose bool) {
	t.Helper()
	finish := domainFixtureControl(config, exchange.begin, "finish")
	finish.ResponseHash, finish.Disposition = exchange.begin.ResponseHash, "irrevocably-discarded"
	if disclose {
		handoff := domainFixtureControl(config, exchange.begin, "handoff")
		handoff.Proof = authority.issue(exchange.intent, "handoff", &exchange.begin.Lease, exchange.begin.Lease.PrincipalID)
		var permit engine.DomainPermit
		if err := engine.DecodeDomainJSON(domainFixtureControlCall(t, handoff), &permit); err != nil {
			t.Fatal(err)
		}
		finish.PermitID, finish.Disposition = permit.PermitID, "handed-off"
	}
	_ = domainFixtureControlCall(t, finish)
	_ = domainFixtureControlCall(t, finish)
}
func pngFixtureRead(t *testing.T, handle *Handle, config DomainConfig, authority *pngFixtureAuthority, family, key string, fields []string) pngFixtureExchange {
	request := pngstore.Request{ContractRevision: pngstore.Revision, Scope: engine.DomainScope{AccountID: "fixture-account", Product: "manifest"}, Action: "fixture.read", Query: pngstore.Query{Family: family, Key: key, Limit: 10, Fields: fields}}
	return pngFixtureCall(t, handle, config, authority, request, "read", "fixture-human")
}
func pngFixtureRecord(t *testing.T, exchange pngFixtureExchange) pngstore.Record {
	t.Helper()
	var result struct {
		Records []pngstore.Record `json:"records"`
		Result  interface{}       `json:"result"`
	}
	raw := domainFixtureJSON(t, exchange.body["data"])
	if err := engine.DecodeDomainJSON(raw, &result); err != nil || len(result.Records) != 1 {
		t.Fatal("retained typed result missing", err)
	}
	return result.Records[0]
}
