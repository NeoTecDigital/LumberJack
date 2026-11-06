// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/products/pngstore"
)

var pngProfilePages = flag.Int("png-import-profile-pages", 0, "Explicit bounded synthetic native import profiling only")

func TestPNGImportPerformanceProfile(t *testing.T) {
	if *pngProfilePages == 0 {
		t.Skip("explicit diagnostic requested only")
	}
	if *pngProfilePages < 1 || *pngProfilePages > 20 {
		t.Fatal("diagnostic page bound")
	}
	config := pngFixtureConfig()
	config.Scopes[0].Bounds.MaxChanges = 60
	config.Scopes[0].Bounds.MaxNodes = 2000
	config.Scopes[0].Bounds.MaxReceipts = 100
	config.Scopes[0].Bounds.MaxScopeBytes = 67108864
	config.Scopes[0].Bounds.MaxSnapshotBytes = 134217728
	config.MaxRequestBytes = 1048576
	config.MaxResponseBytes = 1048576
	authority := pngFixtureVerifier(t, &config)
	handle := openPNGFixture(t, provisionPNGFixture(t, config), config)
	defer closePNGFixture(t, handle)
	for page := 0; page < *pngProfilePages; page++ {
		start := time.Now()
		read := pngFixtureRead(t, handle, config, authority, "business:job", "absent", []string{"id", "account_id", "name"})
		revision := read.body["revision"].(string)
		pngFixtureFinish(t, config, authority, read, false)
		request := pngFixtureCreate(revision)
		request.CommandID = fmt.Sprintf("profile-page-%d", page)
		request.Mutations = pngProfileMutations(page)
		created := pngFixtureCall(t, handle, config, authority, request, "command", "fixture-human")
		pngFixtureFinish(t, config, authority, created, true)
		t.Logf("LABELLED native diagnostic page=%d records=%d elapsed=%s", page+1, (page+1)*60, time.Since(start))
	}
}

func pngProfileMutations(page int) []pngstore.Mutation {
	result := make([]pngstore.Mutation, 0, 60)
	attributes := map[string]interface{}{}
	for field := 0; field < 30; field++ {
		attributes[fmt.Sprint(field)] = []interface{}{"synthetic exact field", 123.5, nil, true}
	}
	for row := 0; row < 60; row++ {
		id := fmt.Sprintf("profile-%d-%d", page, row)
		data := map[string]interface{}{"id": id, "account_id": "fixture-account", "name": "LABELLED diagnostic", "attributes": attributes}
		result = append(result, pngstore.Mutation{Family: "business:job", Key: id, Data: data})
	}
	return result
}
