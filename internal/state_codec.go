package internal

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// What the state file holds, and why it is not the forest as JSON.
//
// THE DEFECT: the forest is a MULTI-PARENT DAG and JSON is a TREE. Marshalling the root wrote every
// node once PER PATH TO IT, so a chain of diamonds cost 2^n. Twelve rungs is 38 real nodes and
// 9.2 MB; sixteen rungs is 50 nodes and 149 MB and 309 ms — built in memory, UNDER THE EXCLUSIVE
// FOREST LOCK, on EVERY mutation, with every other request stalled behind it. It is about sixty
// ordinary API calls from any authenticated user with write on one branch, and the process it
// exhausts is the remote one. It is the same defect the projection carried, on the write path.
//
// THE SHAPE: a FLAT TABLE of nodes keyed by id, each naming its children by id. One entry per node,
// no matter how many parents it has, so the file is bounded by the forest — and the DAG survives
// the round trip exactly rather than being flattened into a tree and rejoined by guesswork.
//
// WHY THE VERSION SNIFF IS OUTSIDE THE JSON. A version key inside it cannot gate anything:
// loadFromFile unmarshals with plain json.Unmarshal, which IGNORES unknown fields, so a build that
// predates this format reads a v2 file, sees no `children` it understands, silently drops the whole
// node table, and rewrites the old shape over it on the next mutation. Silent, permanent, and
// invisible until someone looks for a node that is gone. The sniff is therefore a magic banner in
// front of the sha256 header, where an older build cannot avoid it: that build reads the first 32
// bytes as the hash and then opens a gzip stream at offset 32, and byte 32 of the banner is not a
// gzip identification byte, so it FAILS CLOSED on a rollback instead of truncating the database.
//
// WHY NOT id REFERENCES IN THE EXISTING NESTED SHAPE, gated by nothing, now that the loader rejoins
// by id. Two reasons, and either is enough. First, "first occurrence wins" then depends on the
// writer emitting a node's body at the same reach the loader considers first: a depth-first writer
// emits the body deep and a bare reference shallow, the breadth-first rejoin meets the reference
// first, and the body is the copy that gets discarded. Measured, not supposed. Second, it leaves
// the downgrade above wide open — an older build reads a reference as a real node with no name, no
// children and no users, and writes that back. A file it cannot read is better than a file it
// quietly empties.
//
// WHAT AN OLD FILE DOES. Every build from 89fbaf9 onward could write a diamond, so a file in the
// old shape may genuinely contain one. Those files are still read — the loader recognises the
// absence of the banner — and core.Canonicalize rejoins the duplicated occurrences, which is exact
// because every occurrence of one id in such a file is a serialization of the same object. The file
// is rewritten in the new shape by the first mutation, not by the load: loading is a read.

// stateMagic marks a state file written as a flat node table. It sits in FRONT of the sha256
// header, which is the only place an older build cannot ignore it.
//
// Its length and its 33rd byte are the load-bearing part, and stateMagicFailsClosed asserts both:
// an older build reads bytes 0..31 as the hash and then hands byte 32 onward to gzip.NewReader, so
// as long as that byte is not gzip's first identification byte the rollback fails at the reader
// rather than inside the data.
const stateMagic = "LUMBERJACK-STATE-2\nthis file is a flat node table\n"

// stateVersion is recorded inside the document as well, for a human reading a decompressed file and
// for a future format to branch on once it is past the banner. It gates NOTHING on its own.
const stateVersion = 2

// stateDocument is the whole forest: which node is the root, and every node exactly once.
//
// LogSequence is set only by tiered persistence: the newest hot-log record this document already
// contains, so recovery replays the log from the record after it. It is INSIDE the document so it
// is written atomically with the forest it describes. Snapshot mode leaves it zero and omitted,
// which keeps that mode's bytes exactly what they were.
type stateDocument struct {
	Version     int                    `json:"version"`
	Root        string                 `json:"root"`
	LogSequence uint64                 `json:"log_sequence,omitempty"`
	Nodes       map[string]*nodeRecord `json:"nodes"`
}

// stateTable is a document read back with each node still as the bytes the file held, so a
// tiered open can seed its change cache without encoding the forest a second time.
type stateTable struct {
	Version     int                        `json:"version"`
	Root        string                     `json:"root"`
	LogSequence uint64                     `json:"log_sequence,omitempty"`
	Nodes       map[string]json.RawMessage `json:"nodes"`
	records     map[string]*nodeRecord
}

// nodeRecord is one node, with its children named by id instead of nested inside it.
//
// The node is EMBEDDED rather than restated field by field, so a field added to core.Node is
// persisted without this file having to be told about it — a serializer that lists the fields it
// knows is a serializer that silently stops saving the next one. The outer Children shadows
// core.Node's own by JSON's shallower-field rule, which is what turns the nesting into ids.
//
// THE TRAP THE SHADOW SETS. Any field added HERE whose json name collides with one of core.Node's
// swallows that field the same way and says nothing, and a second core.Node field tagged
// `json:"children"` would make encoding/json drop BOTH of them, so the real children would stop
// being written while the outer list kept the key populated. Neither is caught by anything at
// compile time. state_codec_test.go asserts, reflectively and over whatever core.Node holds at the
// time, that every field a node carries reaches the file, that `children` is the only shadow, and
// that no two node fields claim one name.
type nodeRecord struct {
	*core.Node
	Children []string `json:"children"`
}

// encodeState serializes the whole forest, once per node.
func encodeState(forest *core.Node) ([]byte, error) {
	return encodeStateAt(forest, 0)
}

// encodeStateAt serializes the whole forest and stamps it with the hot-log sequence it contains.
func encodeStateAt(forest *core.Node, logSequence uint64) ([]byte, error) {
	if forest == nil {
		return nil, fmt.Errorf("cannot serialize a forest that is not there")
	}

	document := stateDocument{
		Version:     stateVersion,
		Root:        forest.ID,
		LogSequence: logSequence,
		Nodes:       make(map[string]*nodeRecord),
	}
	walkForest(forest, func(node *core.Node, children []string) {
		document.Nodes[node.ID] = &nodeRecord{Node: node, Children: children}
	})
	return json.Marshal(document)
}

// walkForest visits every node reachable from the root exactly once, shallowest first, with its
// child ids sorted. It is the one definition of which nodes a serialization holds: the state file
// and the change detection that feeds the hot log walk the same way, so they agree on what is in
// the forest.
func walkForest(forest *core.Node, visit func(node *core.Node, children []string)) {
	seen := map[string]bool{}
	queue := []*core.Node{forest}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if seen[node.ID] {
			continue
		}
		seen[node.ID] = true

		children := make([]string, 0, len(node.Children))
		for _, child := range node.Children {
			if child == nil {
				continue
			}
			children = append(children, child.ID)
			queue = append(queue, child)
		}
		// Sorted so that one forest has one serialization: ranging a Go map does not, and an
		// unstable encoding makes the "nothing changed" hash comparison answer differently every
		// time it is asked.
		sort.Strings(children)
		visit(node, children)
	}
}

// childIDs is a node's children by id, sorted, as the state codec names them.
func childIDs(node *core.Node) []string {
	children := make([]string, 0, len(node.Children))
	for _, child := range node.Children {
		if child != nil {
			children = append(children, child.ID)
		}
	}
	sort.Strings(children)
	return children
}

// decodeState rebuilds the forest from a flat node table, restoring the edges the ids stand for.
func decodeState(data []byte) (*core.Node, error) {
	table, err := decodeTable(data)
	if err != nil {
		return nil, err
	}
	return linkTable(table)
}

// decodeTable reads the node table without linking it, keeping each node's bytes.
func decodeTable(data []byte) (*stateTable, error) {
	var table stateTable
	if err := json.Unmarshal(data, &table); err != nil {
		return nil, err
	}
	table.records = make(map[string]*nodeRecord, len(table.Nodes))
	for id, raw := range table.Nodes {
		var record nodeRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, fmt.Errorf("node %q: %w", id, err)
		}
		if record.Node == nil {
			continue
		}
		table.records[id] = &record
	}
	return &table, nil
}

// linkTable turns a table into the forest, restoring the edges the ids stand for.
func linkTable(table *stateTable) (*core.Node, error) {
	root, present := table.records[table.Root]
	if !present || root == nil || root.Node == nil {
		return nil, fmt.Errorf("the state file names %q as its root and does not carry it", table.Root)
	}

	// The maps are built BEFORE any of them is filled: a child can be named by a parent that has
	// not been read yet, which is the point of naming it by id.
	for _, record := range table.records {
		record.Node.Children = make(map[string]*core.Node, len(record.Children))
	}

	for _, record := range table.records {
		for _, childID := range record.Children {
			child, known := table.records[childID]
			if !known || child == nil || child.Node == nil {
				// An edge to a node the file does not carry is not an edge. Dropping it is what
				// keeps the graph traversable; keeping it would be a nil child in every walk.
				return nil, fmt.Errorf("node %q names a child %q the state file does not carry",
					record.Node.ID, childID)
			}
			record.Node.Children[childID] = child.Node
		}
	}

	return root.Node, nil
}

// readNestedState reads a file written before the node table existed, and REJOINS it.
//
// Such a file writes a node once per path to it, so a node with two parents comes back as two
// objects carrying one id — see core.Canonicalize. The rejoin is exact because every occurrence of
// one id in such a file is a serialization of the same object.
func (server *Server) readNestedState(data []byte) (*core.Node, error) {
	var loadedForest core.Node
	if err := json.Unmarshal(data, &loadedForest); err != nil {
		server.logger.Failure("Failed to unmarshal data: %v", err)
		return nil, fmt.Errorf("error validating data: %v", err)
	}

	if forks := core.Canonicalize(&loadedForest); forks > 0 {
		server.logger.Info("Rejoined %d duplicated occurrences of shared nodes while loading the state file", forks)
	}
	return &loadedForest, nil
}

// tableFromForest is the node table of a forest that was read in another shape — the nested
// legacy file, or the sealed one — so every load ends in one shape for the store to open.
func tableFromForest(forest *core.Node) (*stateTable, error) {
	data, err := encodeState(forest)
	if err != nil {
		return nil, err
	}
	return decodeTable(data)
}
