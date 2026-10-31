// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/NeoTecDigital/LumberJack/products/momentum"
)

func pngACLStateNodes(t *testing.T, directory string) map[string]map[string]interface{} {
	t.Helper()
	raw, _ := pngACLStateFile(t, directory)
	reader, err := gzip.NewReader(bytes.NewReader(raw[len(pngACLStateMagic)+32:]))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Nodes map[string]map[string]interface{} `json:"nodes"`
	}
	if err = json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document.Nodes
}

func pngACLStoredList(t *testing.T, directory, kind, key string) map[string]interface{} {
	t.Helper()
	for _, node := range pngACLStateNodes(t, directory) {
		if node["kind"] == kind {
			metadata, _ := node["metadata"].(map[string]interface{})
			list, _ := metadata[key].(map[string]interface{})
			return list
		}
	}
	t.Fatal("labelled record absent from the state file")
	return nil
}

func TestPNGCreatedRecordStoresAReferenceAndKeepsItsDecisions(t *testing.T) {
	config := pngFixtureConfig()
	authority := pngFixtureVerifier(t, &config)
	directory := provisionPNGFixture(t, config)
	handle := openPNGFixture(t, directory, config)
	read := pngFixtureRead(t, handle, config, authority, "business:job", "absent", []string{"id"})
	request := pngFixtureCreate(read.body["revision"].(string))
	pngFixtureFinish(t, config, authority, read, false)
	created := pngFixtureCall(t, handle, config, authority, request, "command", "fixture-human")
	pngFixtureFinish(t, config, authority, created, true)
	record := pngFixtureRecord(t, created)
	closePNGFixture(t, handle)
	stored := pngACLStoredList(t, directory, "fixture.png_record", "fixture.acl")
	if stored["contractRevision"] != "lj.domain.acl.ref/1" || stored["principals"] != nil {
		t.Fatalf("record stored its own list: %v", stored)
	}
	if raw, _ := pngACLStateFile(t, directory); !bytes.HasPrefix(raw, []byte(pngACLStateMagicReferences)) {
		t.Fatal("a forest holding a reference must carry the banner an older build refuses")
	}
	handle = openPNGFixture(t, directory, config)
	defer closePNGFixture(t, handle)
	reopened := pngFixtureRead(t, handle, config, authority, record.Family, record.Key, []string{"id", "account_id", "name"})
	pngFixtureFinish(t, config, authority, reopened, true)
	if len(reopened.body["records"].([]interface{})) != 1 {
		t.Fatal("reference did not authorize the read after a reopen")
	}
	request = pngFixtureCreate(read.body["revision"].(string))
	request.Query.Family, request.Query.Key, request.Query.Limit, request.Query.Fields = record.Family, record.Key, 1, []string{"id", "secret"}
	input := pngFixtureInput(t, request, "read")
	intent := pngFixtureResolve(t, handle, input)
	proof := authority.issue(intent, "admission", nil, "fixture-limited")
	if _, err := handle.DomainCall(domainFixtureJSON(t, DomainRequest{DomainInput: input, RequestID: "limited-denied", Proof: proof})); err == nil {
		t.Fatal("limited principal read a field its template does not grant")
	}
}

func TestMomentumCreatedRecordKeepsItsPermissionThroughTheTemplate(t *testing.T) {
	config := momentumFixtureConfig()
	momentumFixtureVerifier(t, &config)
	directory := provisionMomentumFixture(t, config)
	handle := openMomentumFixture(t, config, directory)
	read := momentumInput(t, "read", "", "", nil)
	before := momentumResult(t, handle, config, read)
	init := momentumInput(t, momentum.Initialize, "initialize-permission", before["revision"].(string), map[string]interface{}{"nodeId": "product-root"})
	assertMomentumStatus(t, momentumResult(t, handle, config, init), "applied")
	current := momentumResult(t, handle, config, read)
	create := momentumInput(t, momentum.Create, "create-permission", current["revision"].(string), map[string]interface{}{"parentId": "product-root", "title": "LABELLED", "kind": "document", "content": "labelled"})
	assertMomentumStatus(t, momentumResult(t, handle, config, create), "applied")
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	handle = openMomentumFixture(t, config, directory)
	defer handle.Close()
	for _, row := range momentumResult(t, handle, config, read)["nodes"].([]interface{}) {
		node := row.(map[string]interface{})
		if fmt.Sprint(node["permission"]) != "1" {
			t.Fatalf("permission through the template = %v", node["permission"])
		}
	}
}
