// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

var domainFixtureSpec = flag.String("domain-fixture-owner-spec", "", "Explicit synthetic owner provisioning JSON; test-only, never a production API")

type domainFixtureOwnerSpec struct {
	Directory  string                     `json:"directory"`
	Name       string                     `json:"name"`
	ForestID   string                     `json:"forestId"`
	ForestName string                     `json:"forestName"`
	Config     DomainConfig               `json:"config"`
	Records    []domainFixtureOwnerRecord `json:"records"`
}

// Read-only check: does not Open/NewCore/reconcile/rewrite or fabricate a durable receipt.
func TestDomainFixtureVerifyPreservation(t *testing.T) {
	if *domainFixtureSpec == "" {
		t.Skip("explicit fixture owner spec not supplied")
	}
	raw, err := os.ReadFile(*domainFixtureSpec)
	var spec domainFixtureOwnerSpec
	if err != nil || DecodeDomainJSON(raw, &spec) != nil {
		t.Fatal("explicit fixture spec invalid", err)
	}
	file, err := os.Open(filepath.Join(spec.Directory, spec.Name+".dat"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	server := &Server{logger: types.NewLogger()}
	server.stateWriter = newStateWriter(func(stateSnapshot) error { return fmt.Errorf("read-only fixture inspection cannot publish") })
	forest, err := server.readState(file)
	if err != nil {
		t.Fatal(err)
	}
	index, err := stagedForestIndex(forest)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, record := range spec.Records {
		expected, present := record.Metadata["fixture.hidden"]
		if !present {
			continue
		}
		node := index[record.ID]
		if node == nil || !reflect.DeepEqual(expected, node.Metadata["fixture.hidden"]) {
			t.Fatal("native hidden values or exact JSON types changed")
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("explicit fixture supplied no preservation value to check")
	}
	t.Log("read-only real snapshot hidden JSON values/types preserved; no durability claim from loaded state")
}

type domainFixtureOwnerRecord struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Kind     string                 `json:"kind"`
	ParentID string                 `json:"parentId"`
	Metadata map[string]interface{} `json:"metadata"`
}

func TestDomainFixtureProvisionOwner(t *testing.T) {
	if *domainFixtureSpec == "" {
		t.Skip("explicit fixture owner spec not supplied")
	}
	data, err := os.ReadFile(*domainFixtureSpec)
	if err != nil {
		t.Fatal(err)
	}
	var spec domainFixtureOwnerSpec
	if err = DecodeDomainJSON(data, &spec); err != nil {
		t.Fatal(err)
	}
	if err = prepareDomainFixtureDirectory(spec.Directory); err != nil {
		t.Fatal(err)
	}
	server := &Server{logger: types.NewLogger(), cache: &Cache{}, config: types.ServerConfig{Process: types.ProcessInfo{Name: spec.Name, DatabasePath: spec.Directory}}}
	server.stateWriter = newStateWriter(server.publishSnapshot)
	server.forest, err = domainFixtureForest(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, owned := range spec.Config.Scopes {
		if err = server.configureStagedScope(owned.Binding, owned.Bounds); err != nil {
			t.Fatal(err)
		}
	}
	if len(spec.Config.Scopes) == 0 {
		t.Fatal("fixture owner supplied no explicit owned scope")
	}
	t.Log("explicit fixture-owned native snapshot provisioned; no human admission or production defaults")
}
func prepareDomainFixtureDirectory(directory string) error {
	absolute, err := filepath.Abs(directory)
	if err != nil || absolute != directory || !strings.HasPrefix(directory, "/tmp/") {
		return fmt.Errorf("fixture provisioning requires unique absolute /tmp directory")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(directory))
	if err != nil || !strings.HasPrefix(parent, "/tmp/") {
		return fmt.Errorf("fixture owner parent must be real /tmp path")
	}
	if err = os.Mkdir(directory, 0700); err != nil {
		return fmt.Errorf("fixture target must be NEW; refusing existing path")
	}
	return nil
}
func domainFixtureForest(spec domainFixtureOwnerSpec) (*core.Node, error) {
	if spec.Name == "" || spec.ForestID == "" || spec.ForestName == "" || len(spec.Records) == 0 {
		return nil, fmt.Errorf("explicit fixture owner root/records required")
	}
	forest := &core.Node{ID: spec.ForestID, Name: spec.ForestName, Children: map[string]*core.Node{}}
	nodes := map[string]*core.Node{forest.ID: forest}
	for _, record := range spec.Records {
		if record.ID == "" || record.Name == "" || nodes[record.ID] != nil {
			return nil, fmt.Errorf("fixture identity invalid/duplicate")
		}
		nodes[record.ID] = &core.Node{ID: record.ID, Name: record.Name, Kind: record.Kind, Metadata: record.Metadata, Children: map[string]*core.Node{}, Parents: map[string]string{}}
	}
	for _, record := range spec.Records {
		parent := nodes[record.ParentID]
		if parent == nil {
			return nil, fmt.Errorf("fixture parent absent")
		}
		node := nodes[record.ID]
		parent.Children[node.ID] = node
		node.Parents[parent.ID] = parent.Name
	}
	index, err := stagedForestIndex(forest)
	if err != nil || len(index) != len(nodes) {
		return nil, fmt.Errorf("fixture closure incomplete/conflicting")
	}
	return forest, nil
}
