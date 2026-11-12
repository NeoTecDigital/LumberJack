// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// Exact numbers survive every persistence a store can be in (docs/extension-api.md §7.2, §7.8.3).
// A float decode turns 1.50 into 1.5 and rounds 12345678901234567890; json.Number keeps the literal.

var compatExactNumbers = map[string]json.Number{"price": "1.50", "big": "12345678901234567890", "tiny": "1.2300e+4"}

func compatPlantNumbers(t *testing.T, server *Server, name string) {
	t.Helper()
	err := server.changeForest(func() error {
		node := core.NewNode(core.LeafNode, name)
		node.Parents = map[string]string{server.forest.ID: server.forest.Name}
		node.Metadata = map[string]interface{}{}
		for key, value := range compatExactNumbers {
			node.Metadata[key] = value
		}
		server.forest.Children[node.ID] = node
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func compatRequireNumbers(t *testing.T, server *Server, name string) {
	t.Helper()
	server.forestMutex.RLock()
	defer server.forestMutex.RUnlock()
	for _, child := range server.forest.Children {
		if child.Name != name {
			continue
		}
		for key, want := range compatExactNumbers {
			if got, ok := child.Metadata[key].(json.Number); !ok || got != want {
				t.Errorf("metadata %q came back as %#v, want the literal %s", key, child.Metadata[key], want)
			}
		}
		return
	}
	t.Fatalf("node %q is gone", name)
}

func TestExactNumbersSurviveAPlaintextRestart(t *testing.T) {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	server, dir := newStockServer(t)
	compatPlantNumbers(t, server, "numbers")
	_ = server.Shutdown(context.Background())
	compatRequireNumbers(t, reloadServer(t, dir), "numbers")
}

// F1: the encrypted path decoded every node with a plain json.Unmarshal on both encode and decode,
// so an encrypted store rounded its numbers on every write.
func TestExactNumbersSurviveAnEncryptedRestart(t *testing.T) {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", storageTestKey(t))
	server, dir := newStockServer(t)
	compatPlantNumbers(t, server, "numbers")
	_ = server.Shutdown(context.Background())
	compatRequireNumbers(t, reloadServer(t, dir), "numbers")
}

func TestExactNumbersSurviveATieredReplay(t *testing.T) {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	compatPlantNumbers(t, server, "numbers")
	compatRequireNumbers(t, reopenWith(t, server, config, false), "numbers")
}

func TestExactNumbersSurviveATieredSnapshot(t *testing.T) {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	config := tieredConfig(t, types.HotSyncCommit)
	server := newServerWith(t, config)
	compatPlantNumbers(t, server, "numbers")
	if _, err := server.snapshotCold(); err != nil {
		t.Fatal(err)
	}
	compatRequireNumbers(t, reopenWith(t, server, config, false), "numbers")
}
