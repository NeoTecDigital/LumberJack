package internal

import (
	"encoding/json"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/core"
	"sync"
	"testing"
)

func fixtureHome(t *testing.T, s *Server) (*core.Node, string) {
	t.Helper()
	result := workTestCommand(t, s, "admin", WorkCommand{Command: "initialize", Path: "root", ClientID: "init-fixture"}, 200)
	home := s.forest.Children[result["result"].(map[string]interface{})["id"].(string)]
	return home, "root/" + home.Name
}
func TestCategoryInitializationConcurrencyRenameAndRemoval(t *testing.T) {
	s := setupTestForest(t)
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := s.ApplyWorkCommand("admin", WorkCommand{Command: "initialize", Path: "root", ClientID: fmt.Sprintf("concurrent-%d", n)})
			errors <- err
		}(i)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	home, path := fixtureHome(t, s)
	categories := []*core.Node{}
	for _, child := range home.Children {
		if child.Kind == "category" {
			categories = append(categories, child)
		}
	}
	if len(categories) != 4 {
		t.Fatalf("categories: %d", len(categories))
	}
	keep, removed := categories[0], categories[1]
	err := s.changeForest(func() error {
		keep.Metadata["title"] = "Renamed fixture"
		delete(home.Children, removed.ID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	workTestCommand(t, s, "admin", WorkCommand{Command: "initialize", Path: "root", ClientID: "after-rename"}, 200)
	home, _ = s.getNodeFromPath(path)
	if len(home.Children) != 7 || home.Children[keep.ID].Metadata["title"] != "Renamed fixture" {
		t.Fatal("reseeded or overwrote category")
	}
}
func TestCategoryPartialReceiptRecovery(t *testing.T) {
	s := setupTestForest(t)
	home, _ := fixtureHome(t, s)
	var retained *core.Node
	for id, child := range home.Children {
		if child.Kind != "category" {
			continue
		}
		if child.Metadata["title"] == "Health" {
			retained = child
		} else {
			delete(home.Children, id)
		}
	}
	delete(home.Metadata, categoryMarker)
	delete(home.Metadata, categoryIDs)
	retained.Metadata["title"] = "Renamed fixture"
	home.CommandReceipts = map[string]interface{}{"admin:momentum-default-v1:" + home.ID + ":health": map[string]interface{}{"result": map[string]interface{}{"result": map[string]interface{}{"id": retained.ID}}}}
	if err := s.changeForest(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	workTestCommand(t, s, "admin", WorkCommand{Command: "initialize", Path: "root", ClientID: "recover-partial"}, 200)
	if len(home.Children) != 8 {
		t.Fatalf("wrong count after recovery: %d", len(home.Children))
	}
	raw, _ := json.Marshal(home.Metadata[categoryIDs])
	var ids map[string]string
	_ = json.Unmarshal(raw, &ids)
	if ids["Health"] != retained.ID {
		t.Fatal("legacy identity lost")
	}
}
func TestExamplesCanonicalDAGAndNoReseeding(t *testing.T) {
	s := setupTestForest(t)
	home, path := fixtureHome(t, s)
	result := workTestCommand(t, s, "admin", WorkCommand{Command: "examples", Path: path, ClientID: "examples-fixture", ExampleVersion: 1}, 200)
	branch := home.Children[result["result"].(map[string]interface{})["id"].(string)]
	if len(branch.Children) != 8 {
		t.Fatal("expected eight examples")
	}
	counts := map[string]int{}
	var edited, removed *core.Node
	for _, child := range branch.Children {
		value := nodeTemporal(child)
		counts[value.Type]++
		if value.Outcome == "failed" {
			counts["failed"]++
		}
		if len(child.Parents) >= 3 {
			counts["multiple"]++
		}
		if child.Metadata["momentum.financial_target"] != nil || child.Metadata["reminders_disabled"] != true {
			t.Fatal("unsafe sample defaults")
		}
		if edited == nil {
			edited = child
		} else {
			removed = child
		}
	}
	if counts["intent"] != 3 || counts["action"] != 3 || counts["event"] != 2 || counts["failed"] != 1 || counts["multiple"] < 1 {
		t.Fatalf("wrong examples: %v", counts)
	}
	err := s.changeForest(func() error {
		edited.Metadata["title"] = "Edited sample"
		return s.walkScope("", nil, func(at visit) { delete(at.node.Children, removed.ID) })
	})
	if err != nil {
		t.Fatal(err)
	}
	workTestCommand(t, s, "admin", WorkCommand{Command: "examples", Path: path, ClientID: "examples-reopen", ExampleVersion: 1}, 200)
	if len(branch.Children) != 7 || edited.Metadata["title"] != "Edited sample" {
		t.Fatal("reseeded example edits")
	}
	raw, _ := encodeState(s.forest)
	restored, err := decodeState(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.forest = restored
	workTestCommand(t, s, "admin", WorkCommand{Command: "examples", Path: path, ClientID: "examples-reload", ExampleVersion: 1}, 200)
}
