// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"fmt"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

type stagedProtectedLink struct {
	parent     *core.Node
	child      *core.Node
	key        string
	parentID   string
	parentName string
}

type stagedProtection struct {
	original map[string]*core.Node
	cloned   map[string]*core.Node
	links    []stagedProtectedLink
	hash     string
	reserved map[string]*core.Node
}

func (s *Server) captureStagedProtectionLocked() ([]stagedProtection, error) {
	if len(s.stagedScopes) == 0 {
		return nil, nil
	}
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return nil, err
	}
	var protection []stagedProtection
	for _, scope := range s.stagedScopes {
		guard, err := captureStagedScopeProtection(s.forest, index, scope)
		if err != nil {
			return nil, err
		}
		protection = append(protection, guard)
	}
	return protection, nil
}

func captureStagedScopeProtection(forest *core.Node, index map[string]*core.Node, scope *stagedScope) (stagedProtection, error) {
	nodes, err := stagedClosure(index[scope.descriptor.Binding.RootID], scope.descriptor.Bounds)
	if err != nil {
		return stagedProtection{}, err
	}
	cloned, err := cloneStagedNodes(nodes, scope.descriptor.Bounds)
	if err != nil {
		return stagedProtection{}, err
	}
	data, err := encodeState(index[scope.descriptor.Binding.RootID])
	if err != nil {
		return stagedProtection{}, err
	}
	links, err := stagedAncestorLinks(forest, scope.descriptor.Binding.RootID)
	if err != nil {
		return stagedProtection{}, err
	}
	reserved := map[string]*core.Node{}
	if scope.pending != nil {
		reserved = scope.pending.nodes
	}
	return stagedProtection{original: nodes, cloned: cloned, links: links, hash: stagedHash(data), reserved: reserved}, nil
}

func stagedAncestorLinks(root *core.Node, target string) ([]stagedProtectedLink, error) {
	paths := map[*core.Node][]stagedProtectedLink{root: nil}
	queue := []*core.Node{root}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		if parent.ID == target {
			return paths[parent], nil
		}
		queue = append(queue, stagedAncestorChildren(parent, root, paths)...)
	}
	return nil, fmt.Errorf("owned binding has no reachable ancestor path")
}

func stagedAncestorChildren(parent, root *core.Node, paths map[*core.Node][]stagedProtectedLink) []*core.Node {
	var children []*core.Node
	for key, child := range parent.Children {
		if child == nil || paths[child] != nil || child == root {
			continue
		}
		link := stagedProtectedLink{parent: parent, child: child, key: key, parentID: parent.ID, parentName: parent.Name}
		paths[child] = append(append([]stagedProtectedLink(nil), paths[parent]...), link)
		children = append(children, child)
	}
	return children
}

func stagedProtectionChanged(guard stagedProtection, index map[string]*core.Node) bool {
	for _, link := range guard.links {
		if link.parent.ID != link.parentID || link.parent.Name != link.parentName || link.parent.Children[link.key] != link.child {
			return true
		}
	}
	for id, original := range guard.original {
		if index[id] != original {
			return true
		}
	}
	for id := range guard.reserved {
		if guard.original[id] == nil && index[id] != nil {
			return true
		}
	}
	root := guard.links[len(guard.links)-1].child
	data, err := encodeState(root)
	return err != nil || stagedHash(data) != guard.hash
}

func restoreStagedProtection(guard stagedProtection) {
	for id, node := range guard.original {
		copy := guard.cloned[id]
		clearStagedLegacyFields(node)
		node.ID, node.Type, node.Kind, node.Name = copy.ID, copy.Type, copy.Kind, copy.Name
		node.Parents, node.Metadata, node.CommandReceipts = copy.Parents, copy.Metadata, copy.CommandReceipts
		node.CreatedBy, node.CreatedAt = copy.CreatedBy, copy.CreatedAt
		node.ModifiedBy, node.ModifiedAt = copy.ModifiedBy, copy.ModifiedAt
		node.Children = nil
		if copy.Children != nil {
			node.Children = map[string]*core.Node{}
		}
		for key, child := range copy.Children {
			node.Children[key] = guard.original[child.ID]
		}
	}
	for _, link := range guard.links {
		link.parent.ID = link.parentID
		link.parent.Name = link.parentName
		if link.parent.Children == nil {
			link.parent.Children = map[string]*core.Node{}
		}
		link.parent.Children[link.key] = link.child
	}
}

func (s *Server) verifyStagedProtectionLocked(guards []stagedProtection) error {
	if len(guards) == 0 {
		return nil
	}
	index, indexErr := stagedForestIndex(s.forest)
	violated := indexErr != nil || s.forest != guards[0].links[0].parent
	for _, guard := range guards {
		if !violated && !stagedProtectionChanged(guard, index) {
			continue
		}
		violated = true
	}
	violated = violated || s.validateStagedScopesLocked() != nil
	if violated {
		s.forest = guards[0].links[0].parent
		for _, guard := range guards {
			restoreStagedProtection(guard)
		}
		s.removeStagedExternalAliasesLocked(guards)
		return errStagedProtected
	}
	return nil
}

func (s *Server) removeStagedExternalAliasesLocked(guards []stagedProtection) {
	allowed := map[*core.Node]map[string]*core.Node{}
	protected := map[string]*core.Node{}
	for _, guard := range guards {
		for id, node := range guard.reserved {
			protected[id] = node
		}
		for id, node := range guard.original {
			protected[id], allowed[node] = node, node.Children
		}
		protectStagedAncestorLinks(guard.links, allowed, protected)
	}
	queue := []*core.Node{s.forest}
	seen := map[*core.Node]bool{}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if node == nil || seen[node] {
			continue
		}
		seen[node] = true
		queue = append(queue, removeStagedAliases(node, allowed[node], protected)...)
	}
}

func protectStagedAncestorLinks(links []stagedProtectedLink, allowed map[*core.Node]map[string]*core.Node, protected map[string]*core.Node) {
	for _, link := range links {
		protected[link.parentID], protected[link.child.ID] = link.parent, link.child
		if allowed[link.parent] == nil {
			allowed[link.parent] = map[string]*core.Node{}
		}
		allowed[link.parent][link.key] = link.child
	}
}

func removeStagedAliases(node *core.Node, allowed map[string]*core.Node, protected map[string]*core.Node) []*core.Node {
	removeStagedParentAliases(node, protected)
	var children []*core.Node
	for key, child := range node.Children {
		if child != nil && (protected[child.ID] != nil || isStagedNode(child)) && allowed[key] != child {
			delete(node.Children, key)
			continue
		}
		children = append(children, child)
	}
	return children
}

func removeStagedParentAliases(node *core.Node, protected map[string]*core.Node) {
	if protected[node.ID] != nil {
		return
	}
	for id := range node.Parents {
		if protected[id] != nil {
			delete(node.Parents, id)
		}
	}
}

func (s *Server) validateStagedScopesLocked() error {
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return err
	}
	owned := map[string]*core.Node{}
	for _, scope := range s.stagedScopes {
		nodes, err := stagedClosure(index[scope.descriptor.Binding.RootID], scope.descriptor.Bounds)
		if err != nil {
			return err
		}
		if err := validateStagedOwnership(index, nodes, scope.descriptor); err != nil {
			return err
		}
		for id, node := range nodes {
			owned[id] = node
		}
	}
	return validateStagedMarkedClosure(index, owned)
}

func validateStagedMarkedClosure(index, owned map[string]*core.Node) error {
	for id, node := range index {
		if isStagedNode(node) && owned[id] != node {
			return fmt.Errorf("owned marker was copied outside the accepted closure")
		}
	}
	return nil
}
