// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/internal/compat"
)

// The owned-subtree guard (docs/extension-api.md §4.2, §7.8.7): an ordinary write cannot change an
// owned subtree, the links that reach it, or which nodes carry a marker; the subtree is restored and
// the write refused 403. The declaring extension's own writes may change its own marked nodes.

// ownedFixture is a stock server with a/owned (marked, with a child) and a/public.
func ownedFixture(t *testing.T, marker string) (*Server, *core.Node, *core.Node, *core.Node) {
	t.Helper()
	server, _ := newStockServer(t)
	admin := adminID(t, server)
	var parent, owned, child *core.Node
	// Planted directly and persisted, as a store written before the split holds it: an ordinary
	// write cannot mint a marker, which is what the guard is for.
	if err := plantAndPersist(server, func() error {
		parent = core.NewNode(core.BranchNode, "a")
		parent.Parents = map[string]string{server.forest.ID: server.forest.Name}
		parent.CreatedBy = admin
		owned = core.NewNode(core.BranchNode, "owned")
		owned.Parents = map[string]string{parent.ID: parent.Name}
		owned.CreatedBy = admin
		owned.CommandReceipts = map[string]interface{}{marker: map[string]interface{}{"bounds": map[string]interface{}{"maxNodes": json.Number("10")}}}
		owned.Metadata = map[string]interface{}{"label": "original"}
		child = core.NewNode(core.LeafNode, "inside")
		child.Parents = map[string]string{owned.ID: owned.Name}
		child.CreatedBy = admin
		public := core.NewNode(core.LeafNode, "public")
		public.Parents = map[string]string{parent.ID: parent.Name}
		owned.Children[child.ID] = child
		parent.Children[owned.ID], parent.Children[public.ID] = owned, public
		server.forest.Children[parent.ID] = parent
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return server, parent, owned, child
}

// plantAndPersist changes the forest outside the write path and persists it.
func plantAndPersist(server *Server, plant func() error) error {
	if err := plant(); err != nil {
		return err
	}
	return server.persistState(server.statePath())
}

func requireRefused(t *testing.T, what string, err error) {
	t.Helper()
	var status *apiError
	if !asAPIError(err, &status) || status.status != 403 {
		t.Fatalf("%s answered %v, want 403", what, err)
	}
}

func TestOrdinaryWriteCannotChangeOwnedSubtreeOrItsAncestors(t *testing.T) {
	cases := map[string]func(server *Server, parent, owned, child *core.Node){
		"edit inside":     func(_ *Server, _, _, child *core.Node) { child.Metadata = map[string]interface{}{"x": 1} },
		"edit the root":   func(_ *Server, _, owned, _ *core.Node) { owned.Metadata["label"] = "changed" },
		"rename ancestor": func(_ *Server, parent, _, _ *core.Node) { parent.Name = "renamed" },
		"unlink":          func(_ *Server, parent, owned, _ *core.Node) { delete(parent.Children, owned.ID) },
		"delete ancestor": func(server *Server, parent, _, _ *core.Node) { delete(server.forest.Children, parent.ID) },
		"alias": func(server *Server, _, _, child *core.Node) {
			server.forest.Children[child.ID] = child
			child.Parents[server.forest.ID] = server.forest.Name
		},
		"drop the marker": func(_ *Server, _, owned, _ *core.Node) { delete(owned.CommandReceipts, compat.OwnedScopeMarker) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			server, parent, owned, child := ownedFixture(t, compat.OwnedScopeMarker)
			before, err := encodeState(server.forest)
			if err != nil {
				t.Fatal(err)
			}
			durable, _ := os.ReadFile(server.statePath())
			requireRefused(t, name, server.changeForest(func() error {
				change(server, parent, owned, child)
				return nil
			}))
			after, err := encodeState(server.forest)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatalf("the owned subtree was not restored:\nbefore %s\nafter  %s", before, after)
			}
			if again, _ := os.ReadFile(server.statePath()); string(again) != string(durable) {
				t.Fatal("a refused write reached the disk")
			}
		})
	}
}

// An ordinary write may not mint a marker: a node outside every owned subtree that comes out of a
// change carrying one is refused, and the marker taken off.
func TestOrdinaryWriteCannotMintAMarker(t *testing.T) {
	server, parent, _, _ := ownedFixture(t, compat.OwnedScopeMarker)
	var public *core.Node
	for _, node := range parent.Children {
		if node.Name == "public" {
			public = node
		}
	}
	requireRefused(t, "mint", server.changeForest(func() error {
		public.CommandReceipts = map[string]interface{}{compat.OwnedScopeMarker: map[string]interface{}{}}
		return nil
	}))
	if _, marked := public.CommandReceipts[compat.OwnedScopeMarker]; marked {
		t.Fatal("the minted marker stayed")
	}
	if err := server.changeForest(func() error { public.Metadata = map[string]interface{}{"ordinary": true}; return nil }); err != nil {
		t.Fatalf("an ordinary write outside the owned subtree was refused: %v", err)
	}
}

func TestDeclaringExtensionMayWriteItsOwnMarkedNodes(t *testing.T) {
	const marker = "test.owned/v1"
	server, _, owned, child := ownedFixture(t, marker)
	var host extension.Host
	ext := testExtension{spec: extension.Spec{Name: "owner", Markers: []string{marker}}, attach: func(h extension.Host) (extension.Instance, error) {
		host = h
		return testInstance{}, nil
	}}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
	requireRefused(t, "an ordinary write", server.changeForest(func() error { owned.Metadata["label"] = "ordinary"; return nil }))
	if _, err := host.Change(context.Background(), extension.WriteOp{Key: "own"}, func(tx extension.Tx) error {
		node, err := tx.NodeByPath("a/owned/inside")
		if err != nil {
			return err
		}
		node.Metadata = map[string]interface{}{"written": "by its owner"}
		return nil
	}); err != nil {
		t.Fatalf("the declaring extension's own write was refused: %v", err)
	}
	if child.Metadata["written"] != "by its owner" {
		t.Fatal("the owner's write did not land")
	}
}

// A store written before the split, holding an owned scope with a pending command, opens with the
// scope hidden from generic reads and guarded against ordinary writes, its bytes preserved (§7.8.7).
func TestLegacyOwnedScopeIsHiddenAndGuarded(t *testing.T) {
	t.Setenv("CORRESPONDER_STORAGE_MODE", "")
	dir := t.TempDir()
	var fixture compatManifestEntry
	for _, entry := range compatManifest(t) {
		if entry.Fixture == "plain-owned-scope-numbers" {
			fixture = entry
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "stock.dat"), compatRead(t, fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(StateLockPath(filepath.Join(dir, "stock.dat")), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	server := reloadServer(t, dir)
	if _, err := server.getNodeFromPath("account/data"); err == nil {
		t.Fatal("the owned scope is readable through a generic path")
	}
	record, err := server.forest.GetNode("record-a")
	if err != nil {
		t.Fatal(err)
	}
	requireRefused(t, "a write into the owned scope", server.changeForest(func() error {
		record.Metadata["label"] = "overwritten"
		return nil
	}))
	if record.Metadata["price"] != json.Number("1.50") || record.Metadata["big"] != json.Number("12345678901234567890") {
		t.Fatalf("the owned record's numbers changed: %v", record.Metadata)
	}
}
