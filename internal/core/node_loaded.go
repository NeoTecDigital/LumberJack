// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package core

// A node's state record is the bytes the state file held for it. This build writes those bytes back
// for a node it has not changed, even where its own encoding of the same node would differ: a value a
// product stored as a struct comes back as a map, and a map re-marshals with its keys sorted, so the
// cut build's bytes and this build's bytes for one unchanged node are not the same sequence. Keeping
// the loaded bytes is what makes an untouched store re-encode to the identical document
// (docs/extension-api.md §7.1).
//
// Only the nodes whose bytes differ keep anything; for the rest the fresh encoding IS the loaded one.

type loadedRecord struct {
	raw    []byte
	normal [32]byte
}

// KeepLoadedRecord remembers the bytes a node's record was read from, with the sha256 of this build's
// own encoding of the same record at load. It is set once, at load, before the node is reachable.
func (n *Node) KeepLoadedRecord(raw []byte, normal [32]byte) {
	n.loaded = &loadedRecord{raw: raw, normal: normal}
}

// LoadedRecord answers the loaded bytes when this build's encoding of the record still hashes to
// what it did at load, which is when the node is unchanged since then.
func (n *Node) LoadedRecord(normal func() [32]byte) ([]byte, bool) {
	if n.loaded == nil || normal() != n.loaded.normal {
		return nil, false
	}
	return n.loaded.raw, true
}

// HasLoadedRecord reports whether the node kept the bytes it was read from.
func (n *Node) HasLoadedRecord() bool { return n.loaded != nil }
