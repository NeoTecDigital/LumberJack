// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"sync"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// Only forest structure/content hashes may be reused. Never put a DomainView,
// cloned metadata, receipt, permission, proof, callback or result in this cache.
// Nodes remain forest-private and are read only while the forest lock is held.
type domainScopeSnapshot struct {
	root     *core.Node
	nodes    map[string]*core.Node
	revision string
}

type domainSnapshotKey struct {
	binding    DomainNativeBinding
	bounds     DomainBounds
	descriptor stagedDescriptor
}

type domainSnapshotCache struct {
	mutex      sync.Mutex
	generation uint64
	entries    map[domainSnapshotKey]domainScopeSnapshot
}

// Lock order is always forest lock THEN cache mutex. The builder runs under both
// so concurrent readers share one structural build; no path acquires the forest
// lock from this cache. A prior generation's pointers are dropped on next use.
func (c *domainSnapshotCache) snapshot(generation uint64, reusable bool, key domainSnapshotKey, build func() (domainScopeSnapshot, error)) (domainScopeSnapshot, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if !reusable || c.generation != generation {
		c.entries = nil
		c.generation = generation
	}
	if reusable {
		if previous, present := c.entries[key]; present {
			return previous, nil
		}
	}
	snapshot, err := build()
	if err != nil || !reusable {
		return snapshot, err
	}
	if c.entries == nil {
		c.entries = make(map[domainSnapshotKey]domainScopeSnapshot)
	}
	c.entries[key] = snapshot
	return snapshot, nil
}

func (s *Server) domainScopeSnapshotLocked(owned DomainOwnedScope, scope *stagedScope) (domainScopeSnapshot, error) {
	generation, reusable := s.forestMutex.snapshotGeneration()
	key := domainSnapshotKey{binding: owned.Binding, bounds: owned.Bounds, descriptor: scope.descriptor}
	return s.domainSnapshots.snapshot(generation, reusable, key, func() (domainScopeSnapshot, error) {
		return s.buildDomainScopeSnapshotLocked(owned)
	})
}

func (s *Server) buildDomainScopeSnapshotLocked(owned DomainOwnedScope) (domainScopeSnapshot, error) {
	index, err := stagedForestIndex(s.forest)
	if err != nil {
		return domainScopeSnapshot{}, err
	}
	root := index[owned.Binding.RootID]
	nodes, err := stagedClosure(root, owned.Bounds)
	if err != nil {
		return domainScopeSnapshot{}, err
	}
	revision, err := stagedContentRevision(root)
	if err != nil {
		return domainScopeSnapshot{}, err
	}
	return domainScopeSnapshot{root: root, nodes: nodes, revision: revision}, nil
}
