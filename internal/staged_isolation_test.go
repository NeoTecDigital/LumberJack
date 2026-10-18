// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func TestStagedLegacyMutationIsRestoredEvenOnCallbackError(t *testing.T) {
	server := stagedTestConfigured(t)
	record := stagedTestRecord(t, server.forest)
	err := server.changeForest(func() error {
		record.Metadata["label"] = "forbidden"
		record.Users = []core.User{{ID: "unauthorized-legacy-identity"}}
		server.forest.Metadata = map[string]interface{}{"unrelated": "kept in memory"}
		return errors.New("synthetic callback error")
	})
	if err == nil {
		t.Fatal("generic legacy write changed a protected record")
	}
	stagedTestRequireLabel(t, record, "original")
	if record.Users != nil || server.forest.Metadata["unrelated"] != "kept in memory" {
		t.Fatal("protected restoration lost outside changes or retained unauthorized identity state")
	}
	if err := server.changeForest(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	stored := stagedTestDisk(t, server)
	stagedTestRequireLabel(t, stagedTestRecord(t, stored), "original")
	if stored.Metadata["unrelated"] != "kept in memory" {
		t.Fatal("ordinary subsequent legacy persistence lost its permitted outside effect")
	}
}

func TestStagedLegacyAncestorAndAliasInterferenceIsRestored(t *testing.T) {
	server := stagedTestConfigured(t)
	root, _ := server.forest.GetNode("data-root")
	if err := server.changeForest(func() error {
		server.forest.Children["forbidden-alias"] = root
		delete(server.forest.Children, "account-root")
		return nil
	}); err == nil {
		t.Fatal("owned ancestor deletion/alias insertion was accepted")
	}
	if server.forest.Children["forbidden-alias"] != nil || server.forest.Children["account-root"] == nil {
		t.Fatal("guard detected interference without actually restoring protection")
	}
	if _, err := server.readOwnedScope("owned-scope", stagedTestAllow); err != nil {
		t.Fatalf("restored native scope is unusable: %v", err)
	}
}

func TestStagedLegacyReservedIDCollisionIsNotPublished(t *testing.T) {
	server := stagedTestConfigured(t)
	if err := server.changeForest(func() error {
		server.forest.Children["collision"] = &core.Node{ID: "record-a", Name: "bad duplicate"}
		return nil
	}); err == nil {
		t.Fatal("legacy collision with an owned ID was accepted")
	}
	if server.forest.Children["collision"] != nil {
		t.Fatal("owned collision was only detected, not removed")
	}
	stagedTestRequireLabel(t, stagedTestRecord(t, stagedTestDisk(t, server)), "original")
}

func TestStagedLegacyCacheWalkAndProjectionCannotDiscloseScope(t *testing.T) {
	server := stagedTestConfigured(t)
	if _, err := server.getNodeFromPath("account/data/record"); err == nil {
		t.Fatal("legacy path disclosed owned data")
	}
	if err := server.updateCache(); err != nil {
		t.Fatal(err)
	}
	if _, err := server.getFromCache([]string{"account", "data", "record"}); err == nil {
		t.Fatal("legacy cache disclosed owned data")
	}
	var visited []string
	if err := server.walkScope("", nil, func(at visit) { visited = append(visited, at.node.ID) }); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(visited, ","), "data-root") || strings.Contains(strings.Join(visited, ","), "record-a") {
		t.Fatal("root-wide walker disclosed owned IDs")
	}
	projection, _ := json.Marshal(newNodeView(server.forest, "legacy-native"))
	if strings.Contains(string(projection), "data-root") || strings.Contains(string(projection), "record-a") {
		t.Fatalf("legacy recursive projection disclosed owned IDs: %s", projection)
	}
}

func TestStagedOutsideLegacyPersistFailureKeepsLiveMutation(t *testing.T) {
	server := stagedTestConfigured(t)
	publish := server.stateWriter.write
	server.stateWriter.write = func(stateSnapshot) error { return errors.New("synthetic legacy disk failure") }
	if err := server.changeForest(func() error {
		server.forest.Metadata = map[string]interface{}{"outside": "legacy still live"}
		return nil
	}); err == nil {
		t.Fatal("legacy failed persist was acknowledged")
	}
	if server.forest.Metadata["outside"] != "legacy still live" {
		t.Fatal("new staged protection changed legacy outside no-rollback behavior")
	}
	server.stateWriter.write = publish
	if err := server.changeForest(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if stagedTestDisk(t, server).Metadata["outside"] != "legacy still live" {
		t.Fatal("legacy reconvergence changed outside the owned namespace")
	}
}

func TestStagedLegacyCopiedOwnedAndAncestorArtifactsCannotEscape(t *testing.T) {
	for _, variant := range []string{"owned-same-id", "owned-new-id", "ancestor-same-id", "ancestor-new-id"} {
		t.Run(variant, func(t *testing.T) { stagedTestRejectedCopy(t, variant) })
	}
}

func stagedTestRejectedCopy(t *testing.T, variant string) {
	t.Helper()
	server := stagedTestConfigured(t)
	copy := stagedTestArtifact(t, server, variant)
	err := server.changeForest(func() error {
		server.forest.Children["artifact"] = copy
		return nil
	})
	if err == nil {
		t.Fatal("copy artifact was accepted without ownership")
	}
	if err := server.updateCache(); err != nil {
		t.Fatal(err)
	}
	stagedTestNoLegacyOwnedDisclosure(t, server)
	if child := server.forest.Children["artifact"]; child != nil && (isStagedNode(child) || len(child.Children) != 0) {
		t.Fatal("rejected copied node still carries owned data")
	}
	if err := server.changeForest(func() error { return nil }); err != nil {
		t.Fatalf("rejected artifact poisoned subsequent permitted persistence: %v", err)
	}
	stored := stagedTestDisk(t, server)
	if child := stored.Children["artifact"]; child != nil && (isStagedNode(child) || len(child.Children) != 0) {
		t.Fatal("rejected copied data was later published")
	}
}

func stagedTestArtifact(t *testing.T, server *Server, variant string) *core.Node {
	t.Helper()
	root, _ := server.forest.GetNode("data-root")
	nodes, err := stagedClosure(root, server.stagedScopes["owned-scope"].descriptor.Bounds)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := cloneStagedNodes(nodes, server.stagedScopes["owned-scope"].descriptor.Bounds)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(variant, "owned") {
		copy := copied["record-a"]
		if variant == "owned-new-id" {
			copy.ID = "unregistered-owned-copy"
		}
		return copy
	}
	ancestor := &core.Node{ID: "account-root", Name: "account", Children: map[string]*core.Node{"data-root": copied["data-root"]}}
	if variant == "ancestor-new-id" {
		ancestor.ID = "unregistered-ancestor-copy"
	}
	return ancestor
}

func stagedTestNoLegacyOwnedDisclosure(t *testing.T, server *Server) {
	t.Helper()
	if _, err := server.getNodeFromPath("account/data/record"); err == nil {
		t.Fatal("legacy path disclosed protected content")
	}
	if _, err := server.getFromCache([]string{"account", "data", "record"}); err == nil {
		t.Fatal("legacy cache disclosed protected content")
	}
	var visited []string
	if err := server.walkScope("", nil, func(at visit) { visited = append(visited, at.node.ID) }); err != nil {
		t.Fatal(err)
	}
	projection, _ := json.Marshal(newNodeView(server.forest, "legacy-native"))
	for _, id := range []string{"data-root", "record-a", "unregistered-owned-copy"} {
		if strings.Contains(strings.Join(visited, ","), id) || strings.Contains(string(projection), id) {
			t.Fatal("legacy traversal/projector disclosed owned copied content")
		}
	}
}
