// Written by Richard Christopher, Copyright 2026 Mindfull
package embedded

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/products/momentum"
)

func TestMomentumActualNativeWriteReplayAndTwoReopens(t *testing.T) {
	config := momentumFixtureConfig()
	momentumFixtureVerifier(t, &config)
	directory := provisionMomentumFixture(t, config)
	handle := openMomentumFixture(t, config, directory)
	read := momentumInput(t, "read", "", "", nil)
	before := momentumResult(t, handle, config, read)
	init := momentumInput(t, momentum.Initialize, "initialize-once", before["revision"].(string), map[string]interface{}{"nodeId": "product-root"})
	assertMomentumStatus(t, momentumResult(t, handle, config, init), "applied")
	assertMomentumStatus(t, momentumResult(t, handle, config, init), "replayed")
	current := momentumResult(t, handle, config, read)
	if len(current["nodes"].([]interface{})) != 9 {
		t.Fatal("atomic workspace defaults absent or duplicated")
	}
	create := momentumInput(t, momentum.Create, "create-once", current["revision"].(string), map[string]interface{}{
		"parentId": "product-root", "title": "Retained café", "kind": "document", "content": "original"})
	created := momentumResult(t, handle, config, create)
	assertMomentumStatus(t, created, "applied")
	id := created["data"].(map[string]interface{})["id"].(string)
	assertMomentumStatus(t, momentumResult(t, handle, config, create), "replayed")
	current = momentumResult(t, handle, config, read)
	update := momentumInput(t, momentum.Update, "update-once", current["revision"].(string), map[string]interface{}{
		"nodeId": id, "title": "Retained café", "kind": "document", "content": "updated exactly"})
	assertMomentumStatus(t, momentumResult(t, handle, config, update), "applied")
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		handle = openMomentumFixture(t, config, directory)
		current = momentumResult(t, handle, config, read)
		assertMomentumDocument(t, current, id)
		assertMomentumStatus(t, momentumResult(t, handle, config, create), "replayed")
		if err := handle.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func assertMomentumStatus(t *testing.T, value map[string]interface{}, status string) {
	t.Helper()
	if value["receipt"].(map[string]interface{})["status"] != status {
		t.Fatalf("native receipt did not confirm %s", status)
	}
}

func assertMomentumDocument(t *testing.T, value map[string]interface{}, id string) {
	t.Helper()
	rows := value["nodes"].([]interface{})
	if len(rows) != 10 {
		t.Fatal("native workspace changed/duplicated across reopen")
	}
	for _, row := range rows {
		node := row.(map[string]interface{})
		if node["id"] == id {
			if node["content"] != "updated exactly" || node["createdBy"] != "fixture-human" {
				t.Fatal("native content or real actor changed")
			}
			return
		}
	}
	t.Fatal("actual native work missing")
}

func TestMomentumNativeIsolationRevocationAndHandoff(t *testing.T) {
	config := momentumFixtureConfig()
	revoked := momentumFixtureVerifier(t, &config)
	handle := openMomentumFixture(t, config, provisionMomentumFixture(t, config))
	defer handle.Close()
	read := momentumInput(t, "read", "", "", nil)
	foreign := read
	foreign.Proof = "fixture-other-human"
	if _, err := handle.DomainCall(domainFixtureJSON(t, foreign)); err == nil {
		t.Fatal("another principal bypassed native workspace ACL")
	}
	foreign = read
	foreign.Body = []byte(strings.ReplaceAll(string(read.Body), "fixture-account", "other-account"))
	if _, err := handle.DomainCall(domainFixtureJSON(t, foreign)); err == nil {
		t.Fatal("foreign account adopted another workspace binding")
	}
	begin, received := domainFixtureExchange(t, handle, config, read)
	if strings.Contains(string(received.Body), "fixture.hidden") || strings.Contains(string(received.Body), "never-disclose") {
		t.Fatal("private source metadata leaked")
	}
	revoked.Store(true)
	handoff := domainFixtureControl(config, begin, "handoff")
	handoff.Proof = "fixture-revoked"
	if _, err := DomainControlCall(domainFixtureJSON(t, handoff)); err == nil {
		t.Fatal("revoked live authority obtained handoff")
	}
	if _, err := handle.DomainCall(domainFixtureJSON(t, read)); err == nil {
		t.Fatal("revoked live authority obtained a new read")
	}
	finish := domainFixtureControl(config, begin, "finish")
	finish.ResponseHash, finish.Disposition = begin.ResponseHash, "irrevocably-discarded"
	_ = domainFixtureControlCall(t, finish)
}

func TestMomentumRejectsUnknownFieldsAndStaleRevision(t *testing.T) {
	config := momentumFixtureConfig()
	momentumFixtureVerifier(t, &config)
	handle := openMomentumFixture(t, config, provisionMomentumFixture(t, config))
	defer handle.Close()
	current := momentumResult(t, handle, config, momentumInput(t, "read", "", "", nil))
	init := momentumInput(t, momentum.Initialize, "first", current["revision"].(string), map[string]interface{}{"nodeId": "product-root"})
	assertMomentumStatus(t, momentumResult(t, handle, config, init), "applied")
	stale := momentumInput(t, momentum.Create, "stale", current["revision"].(string), map[string]interface{}{
		"parentId": "product-root", "title": "Rejected", "kind": "document", "content": ""})
	begin, received := domainFixtureExchange(t, handle, config, stale)
	var value map[string]interface{}
	_ = json.Unmarshal(received.Body, &value)
	assertMomentumStatus(t, value, "conflict")
	finish := domainFixtureControl(config, begin, "finish")
	finish.ResponseHash, finish.Disposition = begin.ResponseHash, "irrevocably-discarded"
	_ = domainFixtureControlCall(t, finish)
	bad := momentumInput(t, momentum.Update, "bad", current["revision"].(string), map[string]interface{}{
		"nodeId": "product-root", "title": "Rejected", "kind": "document", "content": "", "grant": "admin"})
	if _, err := handle.DomainResolve(domainFixtureJSON(t, bad.DomainInput)); err == nil {
		t.Fatal("unknown command fields silently discarded")
	}
}
