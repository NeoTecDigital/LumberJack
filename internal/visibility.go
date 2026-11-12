// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"errors"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/internal/compat"
)

// What a generic read may see (docs/extension-api.md §4.2). A node is hidden from every generic read
// when it carries an ownership marker — the compatibility marker a store written before the split
// carries, or one an extension declared — or when a registered VisibilityFilter hides it. An
// extension's own reads (ReadTx) are not filtered: the owner sees its own nodes.
//
// THE RULE IS PURE. It reads only the node, so for one forest state it answers one way, which is
// what lets getFromCache trust lastHash: a rule that read anything else would let the cache and the
// walk disagree. It never encodes and never allocates.

// errOwnedNode is the answer to a generic read of a hidden node.
var errOwnedNode = errors.New("owned namespace requires staged access")

// defaultOwnedMarkers is the marker set of a runtime with no extensions.
var defaultOwnedMarkers = []string{compat.OwnedScopeMarker}

// hiddenLocked reports whether a node is hidden from generic reads. The caller holds the forest.
func (s *Server) hiddenLocked(node *core.Node) bool {
	if node == nil {
		return false
	}
	markers, filters := defaultOwnedMarkers, []extension.VisibilityFilter(nil)
	if s.extensions != nil {
		markers, filters = s.extensions.markers, s.extensions.filters
	}
	for _, marker := range markers {
		if _, marked := node.CommandReceipts[marker]; marked {
			return true
		}
	}
	for _, filter := range filters {
		if filter.HiddenLocked(node) {
			return true
		}
	}
	return false
}
