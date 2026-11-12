// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import "github.com/NeoTecDigital/LumberJack/core"

// What the owned-subtree guard checks after a change, and how it puts back what the change touched.
// See owned_guard.go.

// verifyLocked refuses a change that touched a guarded subtree, after restoring it.
func (capture *markerCapture) verifyLocked() error {
	if !capture.violatedLocked() {
		return nil
	}
	capture.restoreLocked()
	return errOwnedSubtree
}

// owned is every node inside a captured subtree.
func (capture *markerCapture) owned() map[*core.Node]bool {
	owned := map[*core.Node]bool{}
	for _, root := range capture.roots {
		for _, node := range root.original {
			owned[node] = true
		}
	}
	return owned
}

// violatedLocked reports whether the change replaced the forest's root, changed a guarded subtree or
// the links that reach it, linked into a guarded subtree from outside, or put a marker on a node
// outside every guarded subtree.
func (capture *markerCapture) violatedLocked() bool {
	server := capture.server
	if len(capture.roots) > 0 && server.forest != capture.forest {
		return true
	}
	index := subtreeIndex(server.forest)
	for _, root := range capture.roots {
		if root.changed(index) {
			return true
		}
	}
	owned := capture.owned()
	allowed := capture.allowedLinks()
	for _, node := range index {
		if owned[node] {
			continue
		}
		if capture.guarded(node) {
			return true
		}
		for key, child := range node.Children {
			if owned[child] && !allowed[ownedEdge{node, key}] {
				return true
			}
		}
	}
	return false
}

// changed reports whether a subtree's links, membership or encoding moved.
func (root ownedRoot) changed(index map[string]*core.Node) bool {
	for _, link := range root.links {
		if link.parent.ID != link.parentID || link.parent.Name != link.parentName || link.parent.Children[link.key] != link.child {
			return true
		}
	}
	for id, node := range root.original {
		if index[id] != node {
			return true
		}
	}
	top := root.top()
	hash, err := subtreeHash(top)
	return err != nil || hash != root.hash
}

// top is the subtree's marker-bearing root: the end of its ancestor links, or the forest's root.
func (root ownedRoot) top() *core.Node {
	if len(root.links) > 0 {
		return root.links[len(root.links)-1].child
	}
	for _, node := range root.original {
		if len(node.Parents) == 0 {
			return node
		}
	}
	return nil
}

type ownedEdge struct {
	parent *core.Node
	key    string
}

// allowedLinks are the edges into guarded subtrees from outside them: the ancestor links.
func (capture *markerCapture) allowedLinks() map[ownedEdge]bool {
	allowed := map[ownedEdge]bool{}
	for _, root := range capture.roots {
		for _, link := range root.links {
			allowed[ownedEdge{link.parent, link.key}] = true
		}
	}
	return allowed
}

// restoreLocked puts every guarded subtree and its links back as they were captured, drops the
// edges and parent entries the change added into or out of them, and takes off the markers it put
// on nodes outside them.
func (capture *markerCapture) restoreLocked() {
	if len(capture.roots) > 0 {
		capture.server.forest = capture.forest
	}
	for _, root := range capture.roots {
		for id, node := range root.original {
			restoreNodeFields(node, root.cloned[id], root.original)
		}
		for _, link := range root.links {
			link.parent.ID, link.parent.Name = link.parentID, link.parentName
			if link.parent.Children == nil {
				link.parent.Children = map[string]*core.Node{}
			}
			link.parent.Children[link.key] = link.child
		}
	}
	owned, allowed := capture.owned(), capture.allowedLinks()
	ownedIDs := make(map[string]bool, len(owned))
	for node := range owned {
		ownedIDs[node.ID] = true
	}
	for _, node := range subtreeIndex(capture.server.forest) {
		if owned[node] {
			continue
		}
		detachAliases(node, owned, ownedIDs, allowed)
		capture.stripMarkers(node)
	}
}

// detachAliases removes a node's edges into a guarded subtree that are not ancestor links, and its
// parent entries naming a guarded node.
func detachAliases(node *core.Node, owned map[*core.Node]bool, ownedIDs map[string]bool, allowed map[ownedEdge]bool) {
	for key, child := range node.Children {
		if owned[child] && !allowed[ownedEdge{node, key}] {
			delete(node.Children, key)
		}
	}
	for id := range node.Parents {
		if ownedIDs[id] {
			delete(node.Parents, id)
		}
	}
}

// stripMarkers takes the guarded markers off a node outside every guarded subtree: before this
// change it carried none, or it would have been captured as a root.
func (capture *markerCapture) stripMarkers(node *core.Node) {
	if !capture.guarded(node) {
		return
	}
	markers := defaultOwnedMarkers
	if capture.server.extensions != nil {
		markers = capture.server.extensions.markers
	}
	for _, marker := range markers {
		if !capture.exempt[marker] {
			delete(node.CommandReceipts, marker)
		}
	}
	if len(node.CommandReceipts) == 0 {
		node.CommandReceipts = nil
	}
}
