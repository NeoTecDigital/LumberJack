// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func stagedHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func stagedContentRevision(root *core.Node) (string, error) {
	data, err := encodeStateResolved(root, func(node *core.Node) *core.Node {
		return stagedNodeWithoutReceipts(node)
	})
	if err != nil {
		return "", err
	}
	var descriptor stagedDescriptor
	if err := decodeStagedInternal(root.CommandReceipts[stagedScopeKey], &descriptor); err != nil {
		return "", fmt.Errorf("content revision lacks immutable owned binding: %w", err)
	}
	bound, _ := json.Marshal([]interface{}{descriptor.Binding, stagedHash(data)})
	return "lj.owned/v1:" + stagedHash(bound), nil
}

func stagedNodeWithoutReceipts(node *core.Node) *core.Node {
	return &core.Node{ID: node.ID, Type: node.Type, Kind: node.Kind, Name: node.Name,
		Parents: node.Parents, Children: node.Children, Metadata: node.Metadata,
		CreatedBy: node.CreatedBy, CreatedAt: node.CreatedAt,
		ModifiedBy: node.ModifiedBy, ModifiedAt: node.ModifiedAt}
}

func (s *Server) stagedOverlayLocked() map[string]*core.Node {
	overlay := map[string]*core.Node{}
	for _, scope := range s.stagedScopes {
		if scope.pending == nil {
			continue
		}
		for id, node := range scope.pending.nodes {
			overlay[id] = node
		}
	}
	return overlay
}

func (s *Server) encodeSnapshotLocked(path string, updateLiveHash bool) (stateSnapshot, error) {
	live, err := encodeState(s.forest)
	if err != nil {
		return stateSnapshot{}, err
	}
	if updateLiveHash {
		hash := sha256.Sum256(live)
		s.lastHash = append([]byte(nil), hash[:]...)
	}
	data := live
	overlay := s.stagedOverlayLocked()
	if len(overlay) != 0 {
		data, err = encodeStateResolved(s.forest, stagedOverlayResolver(overlay))
	}
	if err != nil {
		return stateSnapshot{}, err
	}
	var pairs map[string]stagedPair
	if len(s.stagedScopes) != 0 {
		pairs, err = stagedPairsFromBytes(data)
		if err != nil {
			return stateSnapshot{}, err
		}
	}
	if err := s.checkStagedSnapshotBoundsLocked(data); err != nil {
		return stateSnapshot{}, err
	}
	hash := sha256.Sum256(data)
	s.stateSeq++
	return stateSnapshot{seq: s.stateSeq, hash: hash[:], data: data, path: path, pairs: pairs}, nil
}

func stagedOverlayResolver(overlay map[string]*core.Node) func(*core.Node) *core.Node {
	return func(node *core.Node) *core.Node {
		if replacement := overlay[node.ID]; replacement != nil {
			return replacement
		}
		return node
	}
}

func (s *Server) checkStagedSnapshotBoundsLocked(data []byte) error {
	for _, scope := range s.stagedScopes {
		if scope.pending != nil && len(data) > scope.descriptor.Bounds.MaxSnapshotBytes {
			return fmt.Errorf("pending owned snapshot exceeds explicit byte bound")
		}
	}
	return nil
}

func stagedPairsFromBytes(data []byte) (map[string]stagedPair, error) {
	var document struct {
		Nodes map[string]json.RawMessage `json:"nodes"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	pairs := map[string]stagedPair{}
	for id, raw := range document.Nodes {
		var node struct {
			Receipts map[string]json.RawMessage `json:"command_receipts"`
		}
		if err := json.Unmarshal(raw, &node); err != nil {
			return nil, err
		}
		if err := stagedNodePairs(id, node.Receipts, pairs); err != nil {
			return nil, err
		}
	}
	return pairs, nil
}

func stagedNodePairs(id string, receipts map[string]json.RawMessage, pairs map[string]stagedPair) error {
	marker, present := receipts[stagedScopeKey]
	if !present {
		return nil
	}
	var descriptor stagedDescriptor
	if strictActivationJSON(marker, &descriptor) != nil || validateStagedBounds(descriptor.Bounds) != nil {
		return fmt.Errorf("invalid owned descriptor in encoded snapshot")
	}
	if id != descriptor.Binding.RootID {
		return nil
	}
	canonical, _ := json.Marshal(descriptor)
	pair := stagedPair{ScopeID: descriptor.Binding.ScopeID, Key: stagedScopeKey,
		Fingerprint: stagedHash(canonical), ReceiptHash: stagedHash(canonical)}
	pairs[stagedPairKey(pair.ScopeID, pair.Key)] = pair
	for key, raw := range receipts {
		if key == stagedScopeKey {
			continue
		}
		pair, err := stagedReceiptPair(descriptor.Binding, key, raw)
		if err != nil {
			return err
		}
		pairs[stagedPairKey(pair.ScopeID, key)] = pair
	}
	return nil
}

// Only the new owned profile gets UseNumber; legacy decoding remains unchanged.
func restoreStagedNumbers(data []byte, document *stateDocument) error {
	owned := false
	for _, record := range document.Nodes {
		owned = owned || record != nil && isStagedNode(record.Node)
	}
	if !owned {
		return nil
	}
	var raw struct {
		Nodes map[string]json.RawMessage `json:"nodes"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for id, record := range document.Nodes {
		if record == nil || !isStagedNode(record.Node) {
			continue
		}
		if err := restoreStagedNodeMetadata(raw.Nodes[id], record.Node); err != nil {
			return err
		}
	}
	return nil
}

func restoreStagedNodeMetadata(raw json.RawMessage, node *core.Node) error {
	var fields struct {
		Metadata json.RawMessage `json:"metadata"`
		Receipts json.RawMessage `json:"command_receipts"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if len(fields.Metadata) != 0 {
		if err := decodeStagedNumbers(fields.Metadata, &node.Metadata); err != nil {
			return err
		}
	}
	return decodeStagedNumbers(fields.Receipts, &node.CommandReceipts)
}

func decodeStagedNumbers(raw json.RawMessage, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(target)
}
