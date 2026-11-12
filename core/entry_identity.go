package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// GIVING AN IDENTITY TO THE ENTRIES THAT ARE ALREADY ON DISK.
//
// Entry.ID is minted at creation, so every entry written from now on carries one. Every entry
// written BEFORE it existed carries the empty string, and an entry with no id is one no route can
// address — which would make DELETE /entries/{id} a route that works only on this week's data.
//
// WHEN: AT LOAD, and durably at the first mutation. The state file is one document rewritten whole
// by the next write, so backfilling in memory at load and letting the ordinary persist carry it to
// disk is the same migration path the v2 flat node table already takes: read-old, write-new on
// first mutation, never write at load. Loading is a read. An install that is only read from is
// never rewritten, and it does not need to be.
//
// WHY DERIVED AND NOT FRESH — this is the load-bearing part. A freshly generated id is different on
// every start, so an install that is loaded, read, and restarted without a single mutation would
// hand out a permalink on Monday that resolves to nothing on Tuesday, and two replicas of one file
// would disagree about what an entry is called. The id is therefore DERIVED from what the file
// already says about where the entry is: the node's id, which holder it is in, which event, and
// which position. Those four are exactly what addressed an entry before ids existed, so the derived
// id is the old address made into a name — computed once, from a file that is not changing while it
// is being read, and identical on every load of that file.
//
// The derived id is stable AFTERWARDS for the reason the fresh one is not: it is stored. The first
// mutation writes it into the document, so the position it was derived from is free to move — a
// deletion below it renumbers indices and the id does not move with them, which is the entire point
// of having an id.
//
// It is NOT derived from the entry's contents. An id that changes when the entry is edited is not
// an identity, and two entries carrying the same text at the same instant are still two entries.

// legacyEntryIDPrefix marks an id that was derived at load rather than minted at creation. It is
// visible on purpose: an operator reading a state file can tell which entries predate identity, and
// nothing has to guess whether an id is old or new in order to keep it.
const legacyEntryIDPrefix = "entry-legacy-"

// BackfillEntryIDs gives every entry in the forest that has no id the id its position derives, and
// reports how many it named.
//
// The walk carries a visit set: the forest is a multi-parent DAG, so a node reachable by two paths
// must be walked once — twice would be harmless, since the second pass finds every id already set,
// but the count it reports would then depend on the shape of the graph rather than on the work.
//
// Nothing is serving yet when this runs; it is called from the load path, before the forest is
// published to the server.
func BackfillEntryIDs(root *Node) int {
	if root == nil {
		return 0
	}

	named := 0
	visited := map[string]bool{root.ID: true}
	queue := []*Node{root}

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		named += node.backfillEntryIDs()

		for _, id := range sortedChildIDs(node.Children) {
			child := node.Children[id]
			if child == nil || visited[child.ID] {
				continue
			}
			visited[child.ID] = true
			queue = append(queue, child)
		}
	}
	return named
}

// backfillEntryIDs names the unnamed entries of one node, in every holder it keeps them in.
func (n *Node) backfillEntryIDs() int {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	named := 0
	for _, run := range n.entryRuns() {
		changed := false
		for index := range run.entries {
			if run.entries[index].ID != "" {
				continue
			}
			run.entries[index].ID = derivedEntryID(n.ID, run.location, index)
			changed = true
			named++
		}
		if changed {
			// Stored back for the same reason every other writer through entryRuns stores back: an
			// Event is a value in a map and the copy this run was read out of is not the stored one.
			run.store(run.entries)
		}
	}
	return named
}

// derivedEntryID is the id an entry's position derives.
//
// Hashed rather than concatenated because an event id is caller-supplied text that may contain
// anything, including the separators a readable form would need. The four inputs are unique within
// a forest by construction — one node id, one holder, one event, one position — so the hash is a
// name for that position and not a guess at one.
func derivedEntryID(nodeID string, at EntryLocation, index int) string {
	seed := fmt.Sprintf("%s\x00%s\x00%s\x00%d", nodeID, at.Holder, at.EventID, index)
	sum := sha256.Sum256([]byte(seed))
	return legacyEntryIDPrefix + hex.EncodeToString(sum[:16])
}
