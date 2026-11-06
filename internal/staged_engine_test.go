// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func TestStagedAppliedPairAndNativePreservation(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "first")
	result, err := server.stageOwnedCommand(command, stagedTestAllow, stagedTestLabel(" exact new label "))
	if err != nil || result.Status != "applied" || result.Durable == nil || result.Durable.Sequence == 0 {
		t.Fatalf("actual staged result = %#v, %v", result, err)
	}
	stored := stagedTestDisk(t, server)
	stagedTestRequireLabel(t, stagedTestRecord(t, stored), " exact new label ")
	root, _ := stored.GetNode("data-root")
	if root.CommandReceipts[stagedCommandKey(command)] == nil {
		t.Fatal("durable snapshot is missing the paired receipt")
	}
	actual, _ := json.Marshal(stagedTestRecord(t, stored).Metadata["unknown"])
	expected, _ := json.Marshal(stagedTestUnknown())
	if string(actual) != string(expected) {
		t.Fatalf("unknown native JSON changed: %s != %s", actual, expected)
	}
}

func TestStagedReplayPrecedesCASAndConflictIsDefinitive(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "stable-id")
	if _, err := server.stageOwnedCommand(command, stagedTestAllow, stagedTestLabel("saved")); err != nil {
		t.Fatal(err)
	}
	neverBuild := func(stagedView) (stagedDelta, error) {
		t.Fatal("a replay executed its setter again")
		return stagedDelta{}, nil
	}
	result, err := server.stageOwnedCommand(command, stagedTestAllow, neverBuild)
	if err != nil || result.Status != "replayed" || result.Durable == nil {
		t.Fatalf("replay = %#v, %v", result, err)
	}
	changed := command
	changed.BodySHA256 = stagedHash([]byte("different body"))
	if _, err := server.stageOwnedCommand(changed, stagedTestAllow, neverBuild); err == nil {
		t.Fatal("same key/different body was not refused")
	}
	stale := command
	stale.CommandID = "new-id"
	if _, err := server.stageOwnedCommand(stale, stagedTestAllow, neverBuild); err == nil {
		t.Fatal("new command bypassed the full-scope CAS")
	}
	stagedTestRequireLabel(t, stagedTestRecord(t, server.forest), "saved")
}

func TestStagedAuthorityAndBoundsFailClosed(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "denied")
	denyField := func(access stagedAccess) error {
		if len(access.Fields) != 0 {
			return errors.New("synthetic data policy denied this field")
		}
		return nil
	}
	if _, err := server.stageOwnedCommand(command, nil, stagedTestLabel("bad")); err == nil {
		t.Fatal("nil authority became an allow fallback")
	}
	if _, err := server.stageOwnedCommand(command, denyField, stagedTestLabel("bad")); err == nil {
		t.Fatal("field denial became an effect")
	}
	if _, err := server.readOwnedScope("owned-scope", nil); err == nil {
		t.Fatal("nil read authority was allowed")
	}
	if server.stagedScopes["owned-scope"].pending != nil {
		t.Fatal("refused command retained a pending effect")
	}
	stagedTestRequireLabel(t, stagedTestRecord(t, server.forest), "original")
	if err := stagedTestServer(t, t.TempDir()).configureStagedScope(stagedTestBinding(), stagedBounds{}); err == nil {
		t.Fatal("missing explicit bounds selected defaults")
	}
}

func TestStagedNativeIDAllocationAndCreation(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "create")
	var id string
	build := func(view stagedView) (stagedDelta, error) {
		var err error
		id, err = view.AllocateID()
		return stagedDelta{Creates: []stagedCreate{{ID: id, ParentID: "data-root",
			Kind: "synthetic-role", Name: "Reusable", Metadata: map[string]interface{}{"label": "Reusable"}}}}, err
	}
	if result, err := server.stageOwnedCommand(command, stagedTestAllow, build); err != nil || result.Status != "applied" {
		t.Fatalf("create = %#v, %v", result, err)
	}
	stored := stagedTestDisk(t, server)
	node, err := stored.GetNode(id)
	if err != nil || !isStagedNode(node) || node.Metadata["label"] != "Reusable" {
		t.Fatalf("native allocated record = %#v, %v", node, err)
	}
	if _, err := server.getNodeFromPath("account/data/Reusable"); err == nil {
		t.Fatal("legacy path disclosed a new owned record")
	}
}

func TestStagedRefusesUnallocatedAndUnsupportedValues(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "invalid-create")
	badCreate := func(stagedView) (stagedDelta, error) {
		return stagedDelta{Creates: []stagedCreate{{ID: "browser-guessed", ParentID: "data-root"}}}, nil
	}
	if _, err := server.stageOwnedCommand(command, stagedTestAllow, badCreate); err == nil {
		t.Fatal("caller-invented native ID was accepted")
	}
	badValue := func(stagedView) (stagedDelta, error) {
		return stagedDelta{Writes: []stagedWrite{{NodeID: "record-a", Key: "label", Value: make(chan int)}}}, nil
	}
	if _, err := server.stageOwnedCommand(command, stagedTestAllow, badValue); err == nil {
		t.Fatal("unsupported preserved type was accepted")
	}
	if server.stagedScopes["owned-scope"].pending != nil {
		t.Fatal("invalid candidate escaped to persistence")
	}
}

func TestStagedRegistrationRefusesAliasesAndLegacyState(t *testing.T) {
	server := stagedTestServer(t, t.TempDir())
	record := stagedTestRecord(t, server.forest)
	server.forest.Children[record.ID] = record
	if err := server.configureStagedScope(stagedTestBinding(), stagedTestBounds()); err == nil {
		t.Fatal("external alias was accepted")
	}
	delete(server.forest.Children, record.ID)
	record.Users = []core.User{{ID: "legacy-user"}}
	if err := server.configureStagedScope(stagedTestBinding(), stagedTestBounds()); err == nil {
		t.Fatal("legacy identity state was cloned into the owned namespace")
	}
}

func TestStagedCandidateCannotMutateUntouchedNativeBag(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "isolated-builder")
	build := func(view stagedView) (stagedDelta, error) {
		view.Records["record-a"].Metadata["unknown"].(map[string]interface{})["bool"] = false
		return stagedDelta{Writes: []stagedWrite{{NodeID: "record-a", Key: "label", Value: "intent only"}}}, nil
	}
	if _, err := server.stageOwnedCommand(command, stagedTestAllow, build); err != nil {
		t.Fatal(err)
	}
	unknown := stagedTestRecord(t, stagedTestDisk(t, server)).Metadata["unknown"].(map[string]interface{})
	if unknown["bool"] != true {
		t.Fatal("candidate builder mutated preserved native data outside its returned delta")
	}
}

func TestStagedScopeBytesAndReceiptCapacityAreExplicit(t *testing.T) {
	server := stagedTestServer(t, t.TempDir())
	bounds := stagedTestBounds()
	bounds.MaxScopeBytes = 10
	if err := server.configureStagedScope(stagedTestBinding(), bounds); err == nil {
		t.Fatal("owned registration exceeded its explicit byte bound")
	}
	if isStagedNode(stagedTestRecord(t, server.forest)) {
		t.Fatal("refused setup changed the original node ownership marker")
	}
	server = stagedTestServer(t, t.TempDir())
	bounds = stagedTestBounds()
	bounds.MaxReceipts = 1
	if err := server.configureStagedScope(stagedTestBinding(), bounds); err != nil {
		t.Fatal(err)
	}
	first := stagedTestCommand(t, server, "capacity-first")
	if _, err := server.stageOwnedCommand(first, stagedTestAllow, stagedTestLabel("kept")); err != nil {
		t.Fatal(err)
	}
	second := stagedTestCommand(t, server, "capacity-second")
	if _, err := server.stageOwnedCommand(second, stagedTestAllow, stagedTestLabel("not applied")); err == nil {
		t.Fatal("receipt capacity silently evicted a deduplication key")
	}
	if result, err := server.stageOwnedCommand(first, stagedTestAllow, stagedTestLabel("kept")); err != nil || result.Status != "replayed" {
		t.Fatalf("retained receipt replay failed: %#v, %v", result, err)
	}
}
