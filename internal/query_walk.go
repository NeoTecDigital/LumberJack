package internal

import (
	"net/http"
	"sort"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// Walking the forest, which is a MULTI-PARENT DAG and not a tree.
//
// A node can be a child of two branches at once — that is the whole point of the structure, and it
// is how an org, a project and a person can all contain the same work. Two consequences that plain
// recursion gets wrong:
//
//  1. A node reachable by two paths would be COUNTED TWICE. A visit set keyed by node id fixes it.
//  2. An edge added back up the graph makes a cycle, and recursion down Children then never
//     returns. The same visit set fixes that too.
//
// The walk is BREADTH-FIRST and each level is ordered BY NAME. Breadth-first so a node reachable at
// two depths is reported at the shallower one, which is the one a depth bound is about; by name so
// that the path a shared node is reported under is the same on every request — Go randomizes map
// iteration, and a result whose node_path changes between two identical queries cannot be paged.

// visit is one node together with how it was reached.
type visit struct {
	node  *core.Node
	path  string
	depth int
}

// walkScope visits every node in the subtree under scope, once each, shallowest first.
//
// scope is a PATH relative to the forest root; empty means the whole forest. depth bounds how far
// below the scope root the walk goes: 0 is the scope root alone, nil is unbounded.
//
// The caller must hold the forest for reading.
func (server *Server) walkScope(scope string, depth *int, visitor func(visit)) error {
	root, err := server.getNodeFromPath(scope)
	if err != nil {
		return apiErrorf(http.StatusNotFound, "%v", err)
	}
	if depth != nil && *depth < 0 {
		return apiErrorf(http.StatusBadRequest, "depth cannot be negative")
	}

	// The scope's own CANONICAL path, which is what every node_path below it is built from. It
	// used to be the scope string as the caller wrote it, so an unscoped query rooted its answers
	// at the forest's name and a scoped one rooted them at whatever the caller typed — two forms
	// out of one route. See node_path.go.
	rootPath := server.canonicalPath(scope)

	visited := map[string]bool{root.ID: true}
	queue := []visit{{node: root, path: rootPath, depth: 0}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		visitor(current)

		if depth != nil && current.depth >= *depth {
			continue
		}

		for _, child := range childrenByName(current.node) {
			if visited[child.ID] {
				continue
			}
			visited[child.ID] = true
			queue = append(queue, visit{
				node:  child,
				path:  current.path + "/" + child.Name,
				depth: current.depth + 1,
			})
		}
	}
	return nil
}

// childrenByName is a node's children in a fixed order.
//
// Ranging a Go map is deliberately randomized, so without this the path a shared node is reported
// under — and therefore the order of a page — differs between two identical requests.
func childrenByName(node *core.Node) []*core.Node {
	children := make([]*core.Node, 0, len(node.Children))
	for _, child := range node.Children {
		children = append(children, child)
	}

	sort.Slice(children, func(a, b int) bool {
		if children[a].Name != children[b].Name {
			return children[a].Name < children[b].Name
		}
		// Two children of the same name are not supposed to exist, but a total order must not
		// depend on that being true.
		return children[a].ID < children[b].ID
	})
	return children
}

// gather collects the candidates a select names from the scope, permission-filtered.
//
// The caller must hold the forest for reading. Every View built here is a projection that does not
// refer back into the forest, so the results outlive the hold safely.
func (server *Server) gather(userID, selecting, scope string, depth *int) ([]candidate, error) {
	var gathered []candidate

	err := server.walkScope(scope, depth, func(at visit) {
		// A node the caller may not read contributes NOTHING — but the walk descends through it
		// anyway, because a permission granted deeper in the tree is not withdrawn by one that was
		// never granted above it.
		if !at.node.CheckPermission(userID, core.ReadPermission) {
			return
		}

		switch selecting {
		case selectNodes:
			gathered = append(gathered, nodeCandidate(at))
		case selectEvents:
			gathered = append(gathered, eventCandidates(at)...)
		case selectEntries:
			gathered = append(gathered, entryCandidates(at)...)
		case selectTime:
			gathered = append(gathered, timeSpanCandidates(at)...)
		}
	})
	if err != nil {
		return nil, err
	}
	return gathered, nil
}

// validSelect reports whether a select names something, and what /query accepts.
func validSelect(selecting string, allowed ...string) bool {
	for _, name := range allowed {
		if selecting == name {
			return true
		}
	}
	return false
}
