package internal

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// The state file and the graph it is supposed to hold.
//
// THE DEFECT: the forest is a DAG, and JSON is a TREE. A node with two parents was written out
// under each of them, so a restart unmarshalled it TWICE — two objects carrying one id. Every route
// then silently operated on whichever of the two the path it was given happened to reach: an event
// started via one parent was invisible via the other, the entry counts disagreed, and a permission
// granted on shared work applied to only one of the two organisations that shared it.

// diamond builds the smallest fork: one leaf that genuinely belongs to two branches.
func diamond(t *testing.T, server *Server, userID string) {
	t.Helper()

	leafFor(t, server, userID, "org/alpha/shared")
	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": "org/beta", "type": "branch",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create org/beta: got %d, want %d", code, http.StatusOK)
	}
	if code := post(t, server.handleLinkNode, userID, map[string]interface{}{
		"parent_path": "org/beta", "child_path": "org/alpha/shared",
	}).Code; code != http.StatusOK {
		t.Fatalf("Link the shared node under org/beta: got %d, want %d", code, http.StatusOK)
	}
}

// A shared node comes back from the state file as ONE object.
func TestReloadKeepsASharedNodeOneObject(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	diamond(t, server, userID)

	viaAlpha, err := server.getNodeFromPath("org/alpha/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via alpha: %v", err)
	}
	viaBeta, err := server.getNodeFromPath("org/beta/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via beta: %v", err)
	}
	if viaAlpha != viaBeta {
		t.Fatalf("The shared node is already two objects in memory")
	}

	loaded := reloadServer(t, dir)
	alpha, err := loaded.getNodeFromPath("org/alpha/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via alpha after a restart: %v", err)
	}
	beta, err := loaded.getNodeFromPath("org/beta/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via beta after a restart: %v", err)
	}

	if alpha.ID != beta.ID {
		t.Fatalf("The two paths reached different nodes: %s and %s", alpha.ID, beta.ID)
	}
	if alpha != beta {
		t.Errorf("A restart forked node %s into two objects with one id", alpha.ID)
	}
}

// A change made through one parent is a change to the node, not to one of its copies.
func TestReloadedSharedNodeIsChangedThroughEitherParent(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	diamond(t, server, userID)

	loaded := reloadServer(t, dir)
	if code := post(t, loaded.handleStartEvent, userID, map[string]interface{}{
		"path": "org/alpha/shared", "event_id": "shift",
	}).Code; code != http.StatusOK {
		t.Fatalf("Start an event via alpha: got %d, want %d", code, http.StatusOK)
	}

	// The SAME event, asked for through the other parent.
	answer := post(t, loaded.handleGetEventEntries, userID, map[string]interface{}{
		"path": "org/beta/shared", "event_id": "shift",
	})
	if answer.Code != http.StatusOK {
		t.Errorf("The event started via alpha is invisible via beta: got %d, want %d: %s",
			answer.Code, http.StatusOK, answer.Body.String())
	}

	// And a grant on shared work applies to everyone who shares it, not to one fork of it.
	reader := addReadUser(t, loaded, "auditor")
	viaAlpha, err := loaded.getNodeFromPath("org/alpha/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via alpha: %v", err)
	}
	if err := viaAlpha.AssignUser(core.User{ID: reader, Username: "auditor"}, core.WritePermission); err != nil {
		t.Fatalf("Failed to grant on the shared node: %v", err)
	}

	viaBeta, err := loaded.getNodeFromPath("org/beta/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via beta: %v", err)
	}
	if !viaBeta.CheckPermission(reader, core.WritePermission) {
		t.Error("A grant made on the shared node via alpha does not hold via beta")
	}
}

// ladder builds n diamonds in a chain: 3n+2 nodes, 4n+... edges, and 2^n distinct paths to the
// bottom of it. Any authenticated user with write on one branch can build it with POST /nodes and
// POST /nodes/link, which is what makes the cost of it a remote one.
func ladder(t *testing.T, server *Server, userID string, rungs int) {
	t.Helper()

	branch := func(path string) {
		t.Helper()
		if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
			"path": path, "type": "branch",
		}).Code; code != http.StatusOK {
			t.Fatalf("Create branch %s: got %d, want %d", path, code, http.StatusOK)
		}
	}

	path := "work"
	branch(path)
	for rung := 1; rung <= rungs; rung++ {
		left := fmt.Sprintf("%s/left-%d", path, rung)
		right := fmt.Sprintf("%s/right-%d", path, rung)
		bottom := fmt.Sprintf("%s/rung-%d", left, rung)
		branch(left)
		branch(right)
		branch(bottom)

		if code := post(t, server.handleLinkNode, userID, map[string]interface{}{
			"parent_path": right, "child_path": bottom,
		}).Code; code != http.StatusOK {
			t.Fatalf("Link rung %d: got %d, want %d", rung, code, http.StatusOK)
		}
		path = bottom
	}
}

// countNodes is how many nodes there really are, counted once each.
func countNodes(root *core.Node) int {
	seen := map[string]bool{}
	queue := []*core.Node{root}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if seen[node.ID] {
			continue
		}
		seen[node.ID] = true
		for _, child := range node.Children {
			queue = append(queue, child)
		}
	}
	return len(seen)
}

// What the persist COSTS is bounded by the size of the forest.
//
// THE DEFECT: persistState marshalled the forest as a TREE, so a node reachable by k paths was
// serialized k times — and a chain of diamonds makes k exponential in the number of nodes. Twelve
// rungs is 38 real nodes and 9.2 MB; sixteen rungs is 50 nodes and 149 MB, built IN MEMORY, UNDER
// THE EXCLUSIVE FOREST LOCK, on EVERY mutation. That is about sixty ordinary API calls from any
// authenticated user with write on their own branch, and the process it kills is the remote one.
//
// The bound asserted here is per NODE, not a fixed number of bytes: what has to be true is that the
// cost of writing the forest is a function of how much forest there is.
func TestPersistIsBoundedByTheSizeOfTheForest(t *testing.T) {
	for _, rungs := range []int{8, 12} {
		server, _ := newStockServer(t)
		userID := adminID(t, server)
		ladder(t, server, userID, rungs)

		payload, err := encodeState(server.forest)
		if err != nil {
			t.Fatalf("Failed to serialize the forest: %v", err)
		}

		nodes := countNodes(server.forest)
		// Generous: a node with no events, entries or attachments encodes to a few hundred bytes,
		// and this has to hold for one carrying its users too.
		if budget := nodes * 4096; len(payload) > budget {
			t.Errorf("%d rungs is %d nodes and %d bytes of state, want under %d",
				rungs, nodes, len(payload), budget)
		}
	}
}

// readTheOldWay is exactly what every build from 89fbaf9 through facf7e3 does with a state file: a
// 32-byte sha256 header, a gzip stream behind it, and plain json.Unmarshal into a core.Node.
//
// It is spelled out here rather than called, because the point is what an OLD binary does with a
// file this one wrote, and that binary is not importable.
func readTheOldWay(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := make([]byte, sha256.Size)
	if _, err := io.ReadFull(file, hash); err != nil {
		return err
	}

	compressed, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer compressed.Close()

	data, err := io.ReadAll(compressed)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(data)
	if !compareHashes(hash, sum[:]) {
		return fmt.Errorf("data hash mismatch, file may be corrupted")
	}

	var forest core.Node
	return json.Unmarshal(data, &forest)
}

// A rollback FAILS CLOSED. It does not read half the forest and write the other half away.
//
// A version key inside the JSON could not do this: json.Unmarshal ignores fields it does not know,
// so an older build would read a flat document, find no nested `children`, keep an empty forest,
// and rewrite the file in the old shape on the next mutation — silently, permanently, and only
// visible to whoever went looking for a node that used to be there. The banner is in front of the
// hash for that reason.
func TestAnOlderBuildRefusesAStateFileItCannotRead(t *testing.T) {
	// The two properties that make the refusal certain rather than likely: the banner reaches past
	// where an old build stops reading the hash, and the byte it finds there is not the one gzip
	// starts with. Asserted, because they are what the guarantee rests on.
	if len(stateMagic) <= sha256.Size {
		t.Fatalf("The banner is %d bytes and an old build reads %d of them as a hash",
			len(stateMagic), sha256.Size)
	}
	if stateMagic[sha256.Size] == 0x1f {
		t.Fatalf("Byte %d of the banner is gzip's first identification byte", sha256.Size)
	}

	server, dir := newStockServer(t)
	userID := adminID(t, server)
	diamond(t, server, userID)

	path := filepath.Join(dir, "stock.dat")
	if err := readTheOldWay(path); err == nil {
		t.Error("A build that predates the node table read the file instead of refusing it")
	}

	// And this build reads its own file.
	if _, err := reloadServer(t, dir).getNodeFromPath("org/beta/shared"); err != nil {
		t.Errorf("The state file this build wrote is not one it can read: %v", err)
	}
}

// writeNestedStateFile writes the shape every build from 89fbaf9 onward wrote: no banner, a 32-byte
// hash, and the forest as nested JSON, with a node appearing once per path to it.
func writeNestedStateFile(t *testing.T, path string, forest *core.Node) {
	t.Helper()

	data, err := json.Marshal(forest)
	if err != nil {
		t.Fatalf("Failed to serialize the forest the old way: %v", err)
	}

	sum := sha256.Sum256(data)
	var file bytes.Buffer
	file.Write(sum[:])
	compressed := gzip.NewWriter(&file)
	if _, err := compressed.Write(data); err != nil {
		t.Fatalf("Failed to compress the forest: %v", err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatalf("Failed to finish compressing the forest: %v", err)
	}
	if err := os.WriteFile(path, file.Bytes(), 0600); err != nil {
		t.Fatalf("Failed to plant the old state file: %v", err)
	}
}

// A file in the OLD shape is still read, diamond and all.
//
// handleLinkNode landed in 89fbaf9, the fourth of the eight commits in this phase, so every build
// since has written a version-less file that CAN contain a node with two parents. Such a file is
// not hypothetical and it is not refused: it is read, and the duplicated occurrences of the shared
// node are rejoined into the one object they were serialized from.
func TestANewBuildReadsAnOldStateFileWithADiamondInIt(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	diamond(t, server, userID)

	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": "org/alpha/shared", "event_id": "recorded-before-the-rollback",
	}).Code; code != http.StatusOK {
		t.Fatalf("Start an event on the shared node: got %d, want %d", code, http.StatusOK)
	}

	writeNestedStateFile(t, filepath.Join(dir, "stock.dat"), server.forest)

	loaded := reloadServer(t, dir)
	alpha, err := loaded.getNodeFromPath("org/alpha/shared")
	if err != nil {
		t.Fatalf("Failed to read an old state file: %v", err)
	}
	beta, err := loaded.getNodeFromPath("org/beta/shared")
	if err != nil {
		t.Fatalf("Failed to reach the shared node via beta: %v", err)
	}

	if alpha != beta {
		t.Errorf("An old file's shared node came back as two objects")
	}
	if _, recorded := alpha.Events["recorded-before-the-rollback"]; !recorded {
		t.Errorf("The event on the shared node did not survive the old file: %v", alpha.Events)
	}
	if len(alpha.Parents) != 2 {
		t.Errorf("The shared node came back with %d parents, want 2", len(alpha.Parents))
	}

	// Loading does not rewrite the file — loading is a read. The FIRST MUTATION migrates it, and
	// what it writes is a file in the new shape that an older build refuses rather than truncates.
	path := filepath.Join(dir, "stock.dat")
	if err := readTheOldWay(path); err != nil {
		t.Errorf("Loading an old file rewrote it: %v", err)
	}
	if code := post(t, loaded.handleCreateNode, userID, map[string]interface{}{
		"path": "org/alpha/after-the-migration",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create a node on a migrated database: got %d, want %d", code, http.StatusOK)
	}
	if err := readTheOldWay(path); err == nil {
		t.Error("The first mutation left the file in a shape an older build would rewrite")
	}
	if _, err := reloadServer(t, dir).getNodeFromPath("org/beta/shared"); err != nil {
		t.Errorf("The migrated file is not one this build can read: %v", err)
	}
}

// Everything a node carries survives the round trip.
//
// The node table embeds core.Node rather than restating its fields, so that a field added to a node
// is persisted without this codec being told about it. This is the assertion that the embedding
// actually does that: a field that stops being written is a field that is silently gone on the next
// restart.
func TestStateFileRoundTripsEverythingANodeCarries(t *testing.T) {
	server, dir := newStockServer(t)
	userID := adminID(t, server)
	diamond(t, server, userID)
	reader := addReadUser(t, server, "auditor")

	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": "org/alpha/shared", "event_id": "shift",
		"metadata": map[string]interface{}{"kind": "inspection"},
	}).Code; code != http.StatusOK {
		t.Fatalf("Start an event: got %d, want %d", code, http.StatusOK)
	}
	if code := post(t, server.handleAppendToEvent, userID, map[string]interface{}{
		"path": "org/alpha/shared", "event_id": "shift", "content": "a recorded observation",
	}).Code; code != http.StatusOK {
		t.Fatalf("Append to the event: got %d, want %d", code, http.StatusOK)
	}
	if code := serveRoute(t, server, "PATCH", "/nodes/org/alpha/shared/metadata", userID,
		map[string]interface{}{CanvasMetadataKey: map[string]interface{}{"x": 12.0}}).Code; code != http.StatusOK {
		t.Fatalf("PATCH metadata: got %d, want %d", code, http.StatusOK)
	}

	before, err := server.getNodeFromPath("org/alpha/shared")
	if err != nil {
		t.Fatalf("Failed to find the shared node: %v", err)
	}
	// CheckPermission is node-local, so the grant has to be ON the node whose round trip is being
	// asserted. It is made through the forest hold and persisted with the next mutation.
	if err := server.changeForest(func() error {
		return before.AssignUser(core.User{ID: reader, Username: "auditor"}, core.ReadPermission)
	}); err != nil {
		t.Fatalf("Failed to grant on the shared node: %v", err)
	}
	beforeNodes := countNodes(server.forest)

	loaded := reloadServer(t, dir)
	after, err := loaded.getNodeFromPath("org/beta/shared")
	if err != nil {
		t.Fatalf("Failed to find the shared node after a restart: %v", err)
	}

	if got := countNodes(loaded.forest); got != beforeNodes {
		t.Errorf("The forest came back with %d nodes, want %d", got, beforeNodes)
	}
	if after.ID != before.ID || after.Name != before.Name || after.Type != before.Type {
		t.Errorf("The node came back as %s/%s/%v, want %s/%s/%v",
			after.ID, after.Name, after.Type, before.ID, before.Name, before.Type)
	}
	if len(after.Parents) != len(before.Parents) {
		t.Errorf("The node came back with %d parents, want %d", len(after.Parents), len(before.Parents))
	}
	if len(after.Users) != len(before.Users) {
		t.Errorf("The node came back with %d users, want %d", len(after.Users), len(before.Users))
	}
	if !after.CheckPermission(reader, core.ReadPermission) {
		t.Error("The reader's grant did not survive the round trip")
	}
	event, present := after.Events["shift"]
	if !present {
		t.Fatalf("The event did not survive the round trip: %v", after.Events)
	}
	if len(event.Entries) != 1 {
		t.Errorf("The event came back with %d entries, want 1", len(event.Entries))
	}
	if event.Metadata["kind"] != "inspection" {
		t.Errorf("The event's metadata came back as %v, want kind=inspection", event.Metadata)
	}
	if after.Metadata[CanvasMetadataKey] == nil {
		t.Errorf("The canvas layout did not survive the round trip: %v", after.Metadata)
	}
	if after.CreatedBy != before.CreatedBy || !after.CreatedAt.Equal(before.CreatedAt) {
		t.Errorf("The node's authorship came back as %s/%v, want %s/%v",
			after.CreatedBy, after.CreatedAt, before.CreatedBy, before.CreatedAt)
	}
}
