package internal

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/vaziolabs/lumberjack/internal/core"
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
type stateDocument struct {
	Version int                    `json:"version"`
	Root    string                 `json:"root"`
	Nodes   map[string]*nodeRecord `json:"nodes"`
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
	if forest == nil {
		return nil, fmt.Errorf("cannot serialize a forest that is not there")
	}

	document := stateDocument{
		Version: stateVersion,
		Root:    forest.ID,
		Nodes:   make(map[string]*nodeRecord),
	}

	queue := []*core.Node{forest}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if _, written := document.Nodes[node.ID]; written {
			continue
		}

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

		document.Nodes[node.ID] = &nodeRecord{Node: node, Children: children}
	}

	return json.Marshal(document)
}

// decodeState rebuilds the forest from a flat node table, restoring the edges the ids stand for.
func decodeState(data []byte) (*core.Node, error) {
	var document stateDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}

	root, present := document.Nodes[document.Root]
	if !present || root == nil || root.Node == nil {
		return nil, fmt.Errorf("the state file names %q as its root and does not carry it", document.Root)
	}

	// The maps are built BEFORE any of them is filled: a child can be named by a parent that has
	// not been read yet, which is the point of naming it by id.
	for _, record := range document.Nodes {
		if record == nil || record.Node == nil {
			continue
		}
		record.Node.Children = make(map[string]*core.Node, len(record.Children))
	}

	for _, record := range document.Nodes {
		if record == nil || record.Node == nil {
			continue
		}
		for _, childID := range record.Children {
			child, known := document.Nodes[childID]
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
