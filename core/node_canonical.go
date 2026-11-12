package core

import "sort"

// Canonicalize collapses the duplicate objects a TREE encoding of a DAG produces.
//
// THE DEFECT IT CLOSES: the forest is a multi-parent DAG and JSON is a tree, so a node with two
// parents is written out under each of them and unmarshalled TWICE — two objects carrying one id.
// Nothing downstream expects that. getNodeFromPath resolves the two paths to the two objects, so an
// event started through one parent is invisible through the other, the entry counts disagree, and a
// permission granted on shared work applies to only one of the organisations that share it.
//
// FIRST OCCURRENCE WINS, and that is exactly right rather than merely cheap: every occurrence of
// one id in a file this program wrote is a serialization of the SAME object, so the occurrences are
// byte-identical and there is nothing to choose between them. The subtree under a discarded
// occurrence is discarded with it because it is the same subtree, reached again.
//
// The traversal is breadth-first with each level ordered by key, so which occurrence is first does
// not depend on Go's randomized map iteration: the same file canonicalises to the same graph every
// time it is read.
//
// It reports how many forks it collapsed, which is zero for every forest that has no shared node
// and for every file written in a format that does not duplicate one.
func Canonicalize(root *Node) int {
	if root == nil {
		return 0
	}

	canonical := map[string]*Node{root.ID: root}
	forks := 0
	queue := []*Node{root}

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		for _, id := range sortedChildIDs(node.Children) {
			child := node.Children[id]
			if child == nil {
				delete(node.Children, id)
				continue
			}

			first, seen := canonical[child.ID]
			if !seen {
				canonical[child.ID] = child
				queue = append(queue, child)
				continue
			}
			if first == child {
				// The ordinary in-memory case: one object reached twice, which is what the DAG is
				// for. Nothing to collapse, and nothing below it left to visit.
				continue
			}

			forks++
			mergeParents(first, child)
			node.Children[id] = first
		}
	}
	return forks
}

// sortedChildIDs fixes the order children are visited in, because ranging a Go map does not.
func sortedChildIDs(children map[string]*Node) []string {
	ids := make([]string, 0, len(children))
	for id := range children {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// mergeParents folds a discarded occurrence's parents into the one that is kept.
//
// Every occurrence carries the WHOLE parents map already, so this changes nothing for a file this
// program wrote. It is here because the alternative — trusting that — silently loses an edge if it
// is ever untrue, and an edge is what makes the node reachable at all.
func mergeParents(keep, discard *Node) {
	if len(discard.Parents) == 0 {
		return
	}
	if keep.Parents == nil {
		keep.Parents = make(map[string]string, len(discard.Parents))
	}
	for id, name := range discard.Parents {
		if _, known := keep.Parents[id]; !known {
			keep.Parents[id] = name
		}
	}
}
