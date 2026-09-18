package core

import (
	"errors"
	"sort"
	"testing"
)

// ParentID and Rank make an entry nestable and reorderable AS DATA — the thing the address
// (node_path, event_id, entry_index) could not express, because an index moves when anything above
// it moves and there was no field to write an order into at all. These tests hold the two node
// methods that write them (AddEntry, PatchEntry) to that promise: a rank round-trips, a parent
// round-trips, and an entry can be re-ranked and re-parented after the fact.

// AddEntry stores the parent and the rank it is given, and answers a copy carrying them, so the
// route can name the entry it just created without reading it back by an index that has already
// moved.
//
// OBSERVED RED before AddEntry set the two fields (go test ./internal/core/ -run AddEntry):
//
//	entry_write_test.go:NN: AddEntry stored parent_id %q, want "reply-to-abc"  (got "")
//	entry_write_test.go:NN: AddEntry stored rank %q, want "a1"                  (got "")
func TestAddEntryStoresParentAndRank(t *testing.T) {
	node := nodeWithWriter("seed-user")

	created := node.AddEntry("a reply", nil, "seed-user", "reply-to-abc", "a1")

	if created.ParentID != "reply-to-abc" {
		t.Errorf("AddEntry answered parent_id %q, want %q", created.ParentID, "reply-to-abc")
	}
	if created.Rank != "a1" {
		t.Errorf("AddEntry answered rank %q, want %q", created.Rank, "a1")
	}
	if created.ID == "" {
		t.Error("AddEntry answered an entry with no id: it must mint one")
	}

	stored := node.Entries[len(node.Entries)-1]
	if stored.ParentID != "reply-to-abc" {
		t.Errorf("AddEntry stored parent_id %q, want %q", stored.ParentID, "reply-to-abc")
	}
	if stored.Rank != "a1" {
		t.Errorf("AddEntry stored rank %q, want %q", stored.Rank, "a1")
	}
	if stored.ID != created.ID {
		t.Errorf("the stored entry's id %q is not the one AddEntry answered %q", stored.ID, created.ID)
	}
}

// PatchEntry merges metadata (a null value deleting its key) and, when a rank or a parent is
// supplied, rewrites it — which is a reorder and a reparent written as data. An absent (nil) rank or
// parent is left alone.
//
// OBSERVED RED before PatchEntry set rank and parent (go test ./internal/core/ -run PatchEntry):
//
//	entry_write_test.go:NN: PatchEntry left rank %q, want "b7"                  (got "a1")
//	entry_write_test.go:NN: PatchEntry left parent_id %q, want "new-parent"     (got "reply-to-abc")
func TestPatchEntryUpdatesMetadataRankAndParent(t *testing.T) {
	node := nodeWithWriter("seed-user")
	created := node.AddEntry("a reply", map[string]interface{}{"pinned": true, "colour": "red"},
		"seed-user", "reply-to-abc", "a1")

	newRank := "b7"
	newParent := "new-parent"
	patch := map[string]interface{}{"colour": nil, "flag": "urgent"} // delete colour, add flag

	updated, err := node.PatchEntry(created.ID, "seed-user", patch, &newRank, &newParent)
	if err != nil {
		t.Fatalf("PatchEntry on a real id failed: %v", err)
	}

	if updated.Rank != "b7" {
		t.Errorf("PatchEntry left rank %q, want %q", updated.Rank, "b7")
	}
	if updated.ParentID != "new-parent" {
		t.Errorf("PatchEntry left parent_id %q, want %q", updated.ParentID, "new-parent")
	}
	if _, present := updated.Metadata["colour"]; present {
		t.Error("PatchEntry did not delete the metadata key set to null")
	}
	if updated.Metadata["flag"] != "urgent" {
		t.Errorf("PatchEntry did not add the new metadata key: %v", updated.Metadata)
	}
	if updated.Metadata["pinned"] != true {
		t.Error("PatchEntry dropped a metadata key the patch did not mention: the merge is a replace")
	}
	if updated.ModifiedBy != "seed-user" {
		t.Errorf("PatchEntry left modified_by %q, want the caller", updated.ModifiedBy)
	}

	// The change is on the STORED entry, not just the returned copy.
	stored := node.Entries[len(node.Entries)-1]
	if stored.Rank != "b7" || stored.ParentID != "new-parent" {
		t.Errorf("the stored entry came back rank=%q parent=%q, want b7/new-parent", stored.Rank, stored.ParentID)
	}
}

// A nil rank or parent is UNCHANGED, so a caller merging one metadata key does not blank the order.
func TestPatchEntryLeavesAbsentFieldsAlone(t *testing.T) {
	node := nodeWithWriter("seed-user")
	created := node.AddEntry("a reply", nil, "seed-user", "reply-to-abc", "a1")

	updated, err := node.PatchEntry(created.ID, "seed-user", map[string]interface{}{"k": "v"}, nil, nil)
	if err != nil {
		t.Fatalf("PatchEntry failed: %v", err)
	}
	if updated.Rank != "a1" {
		t.Errorf("a nil rank changed the stored rank to %q, want it left at a1", updated.Rank)
	}
	if updated.ParentID != "reply-to-abc" {
		t.Errorf("a nil parent changed the stored parent to %q, want it left at reply-to-abc", updated.ParentID)
	}
}

// PatchEntry on an id nobody stored is NOT FOUND, with the sentinel the route answers 404 for.
func TestPatchEntryOnAnAbsentIDReportsNotFound(t *testing.T) {
	node := nodeWithWriter("seed-user")

	_, err := node.PatchEntry("no-such-entry", "seed-user", nil, nil, nil)
	if !errors.Is(err, ErrEntryNotFound) {
		t.Fatalf("PatchEntry on an absent id answered %v, want the not-found sentinel", err)
	}
}

// Entries created with ranks can be ORDERED by the rank the engine stored and returned, and the
// order is a lexicographic STRING sort — the engine stores and returns the opaque key so the client
// can order by it. Created out of rank order on purpose, so a sort that did nothing would fail.
//
// OBSERVED RED before AddEntry stored the rank (go test ./internal/core/ -run SortByRank):
//
//	entry_write_test.go:NN: entries ordered by rank came back [m a z], want [a m z]
func TestEntriesUnderOneHolderSortByRank(t *testing.T) {
	node := nodeWithWriter("seed-user")
	// Insertion order deliberately not rank order.
	node.AddEntry("middle", nil, "seed-user", "", "m")
	node.AddEntry("first", nil, "seed-user", "", "a")
	node.AddEntry("last", nil, "seed-user", "", "z")

	ordered := append([]Entry(nil), node.Entries...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Rank < ordered[j].Rank })

	got := []string{ordered[0].Rank, ordered[1].Rank, ordered[2].Rank}
	want := []string{"a", "m", "z"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entries ordered by rank came back %v, want %v", got, want)
		}
	}
}
