// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/types"
)

// The rules an extension set is held to at Open (docs/extension-api.md §3), and the Host an attached
// instance writes through. No product code is involved.

type testExtension struct {
	spec   extension.Spec
	attach func(extension.Host) (extension.Instance, error)
}

func (e testExtension) Spec() extension.Spec { return e.spec }

func (e testExtension) Attach(host extension.Host) (extension.Instance, error) {
	if e.attach != nil {
		return e.attach(host)
	}
	return testInstance{}, nil
}

type testInstance struct{ closed func() }

func (i testInstance) Close(context.Context) error {
	if i.closed != nil {
		i.closed()
	}
	return nil
}

func named(name string) testExtension { return testExtension{spec: extension.Spec{Name: name}} }

func TestExtensionSetRefusesBadAndDuplicateNames(t *testing.T) {
	for _, set := range [][]extension.Extension{
		{named("Upper")},
		{named("")},
		{named("with space")},
		{named("one"), named("one")},
	} {
		if _, err := validateExtensions(set, false); !errors.Is(err, ErrExtensionSet) {
			t.Errorf("set %q was accepted: %v", ExtensionSetIdentity(set), err)
		}
	}
	if _, err := validateExtensions([]extension.Extension{named("one"), named("two-2")}, false); err != nil {
		t.Fatalf("a valid set was refused: %v", err)
	}
}

func TestExtensionDeclarationsAreDisjointFromEachOtherAndTheEngine(t *testing.T) {
	key := func(name string) []extension.SlotKey { return []extension.SlotKey{{Name: name}} }
	collisions := map[string][]extension.Spec{
		"root key vs root key":     {{Name: "a", Slot: extension.SlotSpec{RootKeys: key("ledger")}}, {Name: "b", Slot: extension.SlotSpec{RootKeys: key("ledger")}}},
		"root key vs engine field": {{Name: "a", Slot: extension.SlotSpec{RootKeys: key("metadata")}}},
		"node key vs engine field": {{Name: "a", Slot: extension.SlotSpec{NodeKeys: key("children")}}},
		"outbox key vs engine":     {{Name: "a", Slot: extension.SlotSpec{OutboxKeys: key("pending")}}},
		"marker vs marker":         {{Name: "a", Markers: []string{"m"}}, {Name: "b", Markers: []string{"m"}}},
		"config part vs engine":    {{Name: "a", ConfigParts: []string{"password"}}},
		"config part vs part":      {{Name: "a", ConfigParts: []string{"x"}}, {Name: "b", ConfigParts: []string{"x"}}},
		"empty declaration":        {{Name: "a", Markers: []string{""}}},
	}
	for name, specs := range collisions {
		set := make([]extension.Extension, len(specs))
		for index, spec := range specs {
			set[index] = testExtension{spec: spec}
		}
		if _, err := validateExtensions(set, false); !errors.Is(err, ErrExtensionSet) {
			t.Errorf("%s was accepted: %v", name, err)
		}
	}
	disjoint := []extension.Extension{
		testExtension{spec: extension.Spec{Name: "a", Slot: extension.SlotSpec{RootKeys: key("ledger")}, Markers: []string{"a.owned/v1"}, ConfigParts: []string{"a"}}},
		testExtension{spec: extension.Spec{Name: "b", Slot: extension.SlotSpec{OutboxKeys: key("ledger")}, Markers: []string{"b.owned/v1"}, ConfigParts: []string{"b"}}},
	}
	if _, err := validateExtensions(disjoint, false); err != nil {
		t.Fatalf("a disjoint set was refused: %v", err)
	}
}

func TestSnapshotOnlyExtensionIsRefusedUnderTieredPersistence(t *testing.T) {
	set := []extension.Extension{testExtension{spec: extension.Spec{Name: "owned", Persistence: extension.SnapshotOnly}}}
	if _, err := validateExtensions(set, false); err != nil {
		t.Fatalf("snapshot persistence refused a SnapshotOnly extension: %v", err)
	}
	server := newServerWith(t, tieredConfig(t, types.HotSyncCommit))
	if err := server.AttachExtensions(set); !errors.Is(err, ErrExtensionSet) || !strings.Contains(err.Error(), "tiered") {
		t.Fatalf("tiered persistence accepted a SnapshotOnly extension: %v", err)
	}
}

// Attach runs in order, a failed attach closes what attached before it, and Close runs in reverse.
func TestExtensionsAttachInOrderAndCloseInReverse(t *testing.T) {
	var events []string
	recorder := func(name string) testExtension {
		return testExtension{spec: extension.Spec{Name: name}, attach: func(extension.Host) (extension.Instance, error) {
			events = append(events, "attach "+name)
			return testInstance{closed: func() { events = append(events, "close "+name) }}, nil
		}}
	}
	failing := testExtension{spec: extension.Spec{Name: "fails"}, attach: func(extension.Host) (extension.Instance, error) {
		return nil, errors.New("no")
	}}
	server, _ := newStockServer(t)
	if err := server.AttachExtensions([]extension.Extension{recorder("one"), recorder("two"), failing}); !errors.Is(err, ErrExtensionSet) {
		t.Fatalf("a failed attach was accepted: %v", err)
	}
	if got := strings.Join(events, ";"); got != "attach one;attach two;close two;close one" {
		t.Fatalf("failed attach sequence %q", got)
	}
	events = nil
	if err := server.AttachExtensions([]extension.Extension{recorder("one"), recorder("two")}); err != nil {
		t.Fatal(err)
	}
	if err := server.AttachExtensions([]extension.Extension{recorder("three")}); !errors.Is(err, ErrExtensionSet) {
		t.Fatal("a second attach was accepted")
	}
	if err := server.CloseExtensions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(events, ";"); got != "attach one;attach two;close two;close one" {
		t.Fatalf("close sequence %q", got)
	}
}

// Host.Change is the engine's write path: the change is durable when it answers, the Commit names
// the durable snapshot, and an extension's *Error is answered as its status. No Host call is
// honoured once the instances are closed.
func TestHostChangeIsDurableAndAnswersTheCommit(t *testing.T) {
	var host extension.Host
	capture := testExtension{spec: extension.Spec{Name: "writer"}, attach: func(h extension.Host) (extension.Instance, error) {
		host = h
		return testInstance{}, nil
	}}
	server, dir := newStockServer(t)
	if err := server.AttachExtensions([]extension.Extension{capture}); err != nil {
		t.Fatal(err)
	}
	commit, err := host.Change(context.Background(), extension.WriteOp{Key: "add"}, func(tx extension.Tx) error {
		root := tx.Root()
		node := core.NewNode(core.LeafNode, "from-extension")
		node.Parents = map[string]string{root.ID: root.Name}
		node.CreatedBy = "writer-user"
		root.Children[node.ID] = node
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if commit.Tiered || commit.Seq != server.stateWriter.durableSeq || commit.Path != server.statePath() ||
		commit.SHA256 != [32]byte(server.stateWriter.durableHash) {
		t.Fatalf("commit %+v does not name the durable snapshot %d", commit, server.stateWriter.durableSeq)
	}
	if _, err := reloadServer(t, dir).getNodeFromPath("from-extension"); err != nil {
		t.Fatalf("the change was not durable: %v", err)
	}
	_, err = host.Change(context.Background(), extension.WriteOp{Key: "refuse"}, func(extension.Tx) error {
		return &extension.Error{Status: 409, Message: "taken"}
	})
	var status *apiError
	if !asAPIError(err, &status) || status.status != 409 {
		t.Fatalf("an extension error came back as %v", err)
	}
	var seen bool
	if err := host.Read(func(tx extension.ReadTx) error {
		node, err := tx.NodeByPath("from-extension")
		seen = err == nil && tx.Permits(node, "writer-user", core.ReadPermission) && !tx.Permits(node, "stranger", core.ReadPermission)
		_, byID := tx.NodeByID(node.ID)
		seen = seen && byID
		return nil
	}); err != nil || !seen {
		t.Fatalf("the extension's read did not see its node: %v", err)
	}
	if err := server.CloseExtensions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Change(context.Background(), extension.WriteOp{}, func(extension.Tx) error { return nil }); !errors.Is(err, errExtensionsClosed) {
		t.Fatalf("a change after close was honoured: %v", err)
	}
}
