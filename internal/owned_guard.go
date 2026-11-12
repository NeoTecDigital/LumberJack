// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
)

// The owned-subtree guard (docs/extension-api.md §4.2), the write-side twin of the visibility rule.
// A node carrying an ownership marker is the root of an owned subtree. An ordinary write may not
// change that subtree, the links that lead to it from the root of the forest, or the set of nodes
// carrying a marker: such a write is refused 403, and the subtree is restored from the clone taken
// before the change. An extension's own Host.Change is exempt for the markers it declared, and only
// for those.
//
// It runs first before a change and last after it, under the exclusive hold, so neither persistence
// can make durable a change it refused.

// errOwnedSubtree is the refusal of an ordinary write that touched an owned subtree.
var errOwnedSubtree = errors.New("an owned subtree is not changed by an ordinary write")

// ownedGuardMaxNodes bounds an owned subtree whose marker names no bound of its own.
const ownedGuardMaxNodes = 100000

type ownedLink struct {
	parent, child        *core.Node
	key                  string
	parentID, parentName string
}

// ownedRoot is one guarded subtree before the change: the nodes in it, their clones, the links that
// reach it from the forest's root, and the hash of its encoding.
type ownedRoot struct {
	original map[string]*core.Node
	cloned   map[string]*core.Node
	links    []ownedLink
	hash     [32]byte
}

func (server *Server) ownedGuard() ownedGuarder { return markerGuard{server: server} }

type markerGuard struct{ server *Server }

type markerCapture struct {
	server *Server
	forest *core.Node
	exempt map[string]bool
	roots  []ownedRoot
}

func (guard markerGuard) captureLocked(op extension.WriteOp) (ownedGuardCapture, error) {
	server := guard.server
	capture := &markerCapture{server: server, forest: server.forest, exempt: server.declaredMarkers(op.Origin)}
	marked := capture.markedNodes(server.forest)
	if len(marked) == 0 {
		return capture, nil
	}
	for _, node := range marked {
		root, err := captureOwnedRoot(server.forest, node, markerBound(node))
		if err != nil {
			return nil, err
		}
		capture.roots = append(capture.roots, root)
	}
	return capture, nil
}

// declaredMarkers are the markers the extension named origin declared: its own writes may change
// the subtrees they mark.
func (server *Server) declaredMarkers(origin string) map[string]bool {
	exempt := map[string]bool{}
	if origin == "" || server.extensions == nil {
		return exempt
	}
	for _, spec := range server.extensions.specs {
		if spec.Name == origin {
			for _, marker := range spec.Markers {
				exempt[marker] = true
			}
		}
	}
	return exempt
}

// markedNodes are the guarded marker-bearing nodes reachable from root, in id order: a node is
// guarded when it carries a marker this write is not exempt for.
func (capture *markerCapture) markedNodes(root *core.Node) []*core.Node {
	var marked []*core.Node
	walkForest(root, func(node *core.Node, _ []string) {
		if capture.guarded(node) {
			marked = append(marked, node)
		}
	})
	sort.Slice(marked, func(a, b int) bool { return marked[a].ID < marked[b].ID })
	return marked
}

func (capture *markerCapture) guarded(node *core.Node) bool {
	markers := defaultOwnedMarkers
	if capture.server.extensions != nil {
		markers = capture.server.extensions.markers
	}
	for _, marker := range markers {
		if _, marked := node.CommandReceipts[marker]; marked && !capture.exempt[marker] {
			return true
		}
	}
	return false
}

// markerBound is the node bound a marker's value names ({"bounds": {"maxNodes": n}}), or the
// engine's.
func markerBound(node *core.Node) int {
	for _, value := range node.CommandReceipts {
		fields, _ := value.(map[string]interface{})
		bounds, _ := fields["bounds"].(map[string]interface{})
		if number, ok := bounds["maxNodes"].(json.Number); ok {
			if bound, err := number.Int64(); err == nil && bound > 0 {
				return int(bound)
			}
		}
	}
	return ownedGuardMaxNodes
}

func captureOwnedRoot(forest, node *core.Node, bound int) (ownedRoot, error) {
	original := subtreeIndex(node)
	if len(original) > bound {
		return ownedRoot{}, fmt.Errorf("owned subtree %s exceeds its bound of %d nodes", node.ID, bound)
	}
	cloned, err := cloneSubtree(original)
	if err != nil {
		return ownedRoot{}, err
	}
	links, err := ownedAncestorLinks(forest, node)
	if err != nil {
		return ownedRoot{}, err
	}
	hash, err := subtreeHash(node)
	if err != nil {
		return ownedRoot{}, err
	}
	return ownedRoot{original: original, cloned: cloned, links: links, hash: hash}, nil
}

// subtreeIndex is every node reachable from root, by id.
func subtreeIndex(root *core.Node) map[string]*core.Node {
	index := map[string]*core.Node{}
	walkForest(root, func(node *core.Node, _ []string) { index[node.ID] = node })
	return index
}

func subtreeHash(root *core.Node) ([32]byte, error) {
	data, err := encodeState(root)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// cloneSubtree copies each node through the record codec, number-exactly, so a restore puts back
// values and not pointers the change may have mutated.
func cloneSubtree(nodes map[string]*core.Node) (map[string]*core.Node, error) {
	cloned := make(map[string]*core.Node, len(nodes))
	for id, node := range nodes {
		raw, err := json.Marshal((*plainNodeRecord)(&nodeRecord{Node: node}))
		if err != nil {
			return nil, err
		}
		var record nodeRecord
		if err := decodeExact(raw, &record); err != nil || record.Node == nil {
			return nil, fmt.Errorf("owned node %s did not clone: %v", id, err)
		}
		record.Node.Children = make(map[string]*core.Node, len(node.Children))
		for key, child := range node.Children {
			record.Node.Children[key] = child
		}
		cloned[id] = record.Node
	}
	return cloned, nil
}

// ownedAncestorLinks is the shortest path of links from the forest's root to the owned root.
func ownedAncestorLinks(forest, target *core.Node) ([]ownedLink, error) {
	if forest == target {
		return nil, nil
	}
	paths := map[*core.Node][]ownedLink{forest: {}}
	queue := []*core.Node{forest}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, key := range sortedChildKeys(parent) {
			child := parent.Children[key]
			if child == nil || paths[child] != nil {
				continue
			}
			link := ownedLink{parent: parent, child: child, key: key, parentID: parent.ID, parentName: parent.Name}
			paths[child] = append(append([]ownedLink(nil), paths[parent]...), link)
			if child == target {
				return paths[child], nil
			}
			queue = append(queue, child)
		}
	}
	return nil, fmt.Errorf("owned root %s has no path from the forest root", target.ID)
}

func sortedChildKeys(node *core.Node) []string {
	keys := make([]string, 0, len(node.Children))
	for key := range node.Children {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// restoreNodeFields puts every exported field of clone back onto node except its children, which
// are relinked to the original nodes so the subtree keeps its identity.
func restoreNodeFields(node, clone *core.Node, original map[string]*core.Node) {
	target, source := reflect.ValueOf(node).Elem(), reflect.ValueOf(clone).Elem()
	for index := 0; index < target.NumField(); index++ {
		field := target.Type().Field(index)
		if field.PkgPath == "" && field.Name != "Children" {
			target.Field(index).Set(source.Field(index))
		}
	}
	node.Children = make(map[string]*core.Node, len(clone.Children))
	for key, child := range clone.Children {
		if held := original[child.ID]; held != nil {
			node.Children[key] = held
		}
	}
}
