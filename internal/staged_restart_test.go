// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestStagedRestartRepublishesAndPreservesUnknownJSON(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "before-restart")
	if _, err := server.stageOwnedCommand(command, stagedTestAllow, stagedTestLabel("survives")); err != nil {
		t.Fatal(err)
	}
	server.forest.Metadata = map[string]interface{}{"legacy-number": json.Number("9007199254740993")}
	if err := server.persistState(server.statePath()); err != nil {
		t.Fatal(err)
	}
	restarted := stagedTestServer(t, server.config.Process.DatabasePath)
	count := 0
	publish := restarted.stateWriter.write
	restarted.stateWriter.write = func(snapshot stateSnapshot) error { count++; return publish(snapshot) }
	if err := restarted.loadFromFile(server.statePath()); err != nil {
		t.Fatal(err)
	}
	if count == 0 || restarted.stateWriter.durableSeq == 0 {
		t.Fatal("loaded memory/hash was treated as a durable receipt without actual publish")
	}
	if _, err := restarted.readOwnedScope("owned-scope", stagedTestAllow); err == nil {
		t.Fatal("restart configured public/native admission implicitly")
	}
	if _, ok := restarted.forest.Metadata["legacy-number"].(float64); !ok {
		t.Fatal("new owned decoder changed legacy number decoding")
	}
	if err := restarted.configureStagedScope(stagedTestBinding(), stagedTestBounds()); err != nil {
		t.Fatal(err)
	}
	assertStagedRestartValues(t, restarted)
	neverBuild := func(stagedView) (stagedDelta, error) {
		t.Fatal("restart replay reapplied setter")
		return stagedDelta{}, nil
	}
	if result, err := restarted.stageOwnedCommand(command, stagedTestAllow, neverBuild); err != nil || result.Status != "replayed" {
		t.Fatalf("restart replay = %#v, %v", result, err)
	}
}

func assertStagedRestartValues(t *testing.T, server *Server) {
	t.Helper()
	record := stagedTestRecord(t, server.forest)
	stagedTestRequireLabel(t, record, "survives")
	unknown := record.Metadata["unknown"].(map[string]interface{})
	if unknown["large"].(json.Number).String() != "9007199254740993" {
		t.Fatal("unknown JSON number lost precision")
	}
	actual, _ := json.Marshal(unknown)
	expected, _ := json.Marshal(stagedTestUnknown())
	if string(actual) != string(expected) {
		t.Fatalf("unknown JSON values changed across restart: %s != %s", actual, expected)
	}
}

func TestStagedRestartUnknownAfterFailedDurableReconciliation(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "restart-failure")
	if _, err := server.stageOwnedCommand(command, stagedTestAllow, stagedTestLabel("survives")); err != nil {
		t.Fatal(err)
	}
	restarted := stagedTestServer(t, server.config.Process.DatabasePath)
	restarted.stateWriter.write = func(stateSnapshot) error { return errors.New("synthetic startup publish failure") }
	if err := restarted.loadFromFile(server.statePath()); err == nil {
		t.Fatal("failed restart reconciliation became ready")
	}
	if _, err := restarted.readOwnedScope("owned-scope", stagedTestAllow); err == nil {
		t.Fatal("failed restart reconciliation disclosed owned state")
	}
	if _, err := restarted.getNodeFromPath("account/data/record"); err == nil {
		t.Fatal("legacy lookup bypassed restored ownership")
	}
}
