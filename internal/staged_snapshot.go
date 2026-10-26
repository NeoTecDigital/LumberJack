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
	var descriptor stagedDescriptor
	if err := decodeStagedInternal(root.CommandReceipts[stagedScopeKey], &descriptor); err != nil {
		return "", fmt.Errorf("content revision lacks immutable binding: %w", err)
	}
	var cloneErr error
	data, err := encodeStateResolved(root, func(node *core.Node) *core.Node {
		if descriptor.SourceProfile != personalExistingProfile {
			return stagedNodeWithoutReceipts(node)
		}
		copy, e := preservedNodeForRevision(node, descriptor.Bounds)
		if e != nil {
			cloneErr = e
			return node
		}
		return copy
	})
	if err != nil {
		return "", err
	}
	if cloneErr != nil {
		return "", cloneErr
	}
	bound, _ := json.Marshal([]interface{}{descriptor.Binding, stagedHash(data)})
	return "lj.owned/v1:" + stagedHash(bound), nil
}
func preservedNodeForRevision(node *core.Node, bounds stagedBounds) (*core.Node, error) {
	copy, err := clonePreservedStagedNode(node, bounds)
	if err != nil {
		return nil, err
	}
	copy.Children = node.Children
	for key := range copy.CommandReceipts {
		if key == stagedScopeKey || isStagedReceiptKey(key) {
			delete(copy.CommandReceipts, key)
		}
	}
	if len(copy.CommandReceipts) == 0 {
		copy.CommandReceipts = nil
	}
	return copy, nil
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
		forest := s.enrollmentOverlayForestLocked(overlay)
		forest.PersonalBindings, err = s.personalOverlayLedgerLocked()
		if err == nil {
			data, err = encodeStateResolved(forest, stagedOverlayResolver(overlay))
		}
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
	if strictActivationJSON(marker, &descriptor) != nil || validateStagedBounds(descriptor.Bounds) != nil || validateEnrollmentDescriptor(descriptor) != nil {
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
		if key == stagedScopeKey || (descriptor.SourceProfile == personalExistingProfile && !isStagedReceiptKey(key)) {
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
	root := document.Nodes[document.Root]
	if root != nil && root.Node != nil && root.PersonalBindings != nil {
		// This protected source profile preserves ALL original interface bags,
		// including unrelated organizations, without changing legacy decoding.
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		return decoder.Decode(document)
	}
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

// Personal enrollment composes its private ledger into the SAME snapshot and
// paired descriptor/receipt; it is neither a second registry nor a data grant.
func (p *personalSource) buildPersonalPendingLocked(e *personalProvisionEntry, actor sourceProvisionVerified) error {
	if p.personalCurrentLocked(e) != nil || e.candidate.State != "absent" {
		return sourceDenied()
	}
	root := newEnrollmentNode(e.candidate.RootID, "workspace", e.candidate.OwnerID)
	root.Parents[p.server.forest.ID] = p.server.forest.Name
	root.Metadata["personal_owner"] = e.candidate.OwnerID
	bindingRevision := sourceCommandKey([]interface{}{e.intent.CommandSHA256, e.candidate.OwnerID, e.candidate.RootID, actor.AccountRegistryRevision})
	binding := stagedBinding{"momentum", bindingRevision, personalScopeID(e.intent.Account.AccountID), e.intent.Account.AccountID, p.server.forest.ID, root.ID}
	descriptor := stagedDescriptor{Binding: binding, Bounds: p.config.StagedBounds}
	root.CommandReceipts[stagedScopeKey] = descriptor
	scope := &stagedScope{descriptor: descriptor}
	ledger, receipt, err := p.personalLedgerCandidateLocked(e, actor, bindingRevision)
	if err != nil {
		return err
	}
	command := personalStagedCommand(e.intent, binding.ScopeID)
	revision, err := validateOwnedCandidate(root, descriptor.Bounds)
	if err != nil {
		return err
	}
	r := stagedReceipt{Version: 1, Command: command, Fingerprint: stagedCommandFingerprint(binding, command), AfterRevision: revision, Targets: []stagedTarget{{NodeID: root.ID, Kind: root.Kind, Fields: []string{"personal_owner"}}}}
	key := stagedCommandKey(command)
	root.CommandReceipts[key] = r
	if _, err = validateOwnedCandidate(root, descriptor.Bounds); err != nil {
		return err
	}
	if p.server.stagedScopes[binding.ScopeID] != nil {
		return sourceDenied()
	}
	pending := &stagedPending{provisionAccount: root, root: root, nodes: map[string]*core.Node{root.ID: root}, receipt: r, key: key}
	scope.pending = pending
	p.server.stagedScopes[binding.ScopeID] = scope
	p.mu.Lock()
	e.scope, e.pending, e.ledger = scope, pending, ledger
	p.mu.Unlock()
	prepared, err := p.server.snapshotOwnedPreparationLocked(scope, pending, key, false)
	if err != nil {
		delete(p.server.stagedScopes, binding.ScopeID)
		p.mu.Lock()
		e.scope, e.pending, e.ledger = nil, nil, nil
		p.mu.Unlock()
		return err
	}
	p.mu.Lock()
	e.snapshot = prepared.snapshot
	p.mu.Unlock()
	_ = receipt // Receipt is only in the private pending ledger until durable commit.
	return nil
}
func personalStagedCommand(i PersonalProvisionIntent, scopeID string) stagedCommand {
	expected := "absent"
	if i.ExpectedBindingRevision != nil {
		expected = *i.ExpectedBindingRevision
	}
	return stagedCommand{i.PrincipalID, i.Account.AccountID, scopeID, i.CommandID, expected, i.Operation, i.CommandSHA256}
}
func (p *personalSource) personalLedgerCandidateLocked(e *personalProvisionEntry, actor sourceProvisionVerified, bindingRevision string) (*core.PersonalBindingLedger, NativePersonalProvisionReceipt, error) {
	ledger := &core.PersonalBindingLedger{Bindings: map[string]core.PersonalBindingRecord{}, Consents: map[string]core.PersonalConsentRecord{}, Receipts: map[string]core.PersonalProvisionRecord{}}
	current := p.server.forest.PersonalBindings
	if current != nil && sourceCanonicalCopy(current, ledger) != nil {
		return nil, NativePersonalProvisionReceipt{}, sourceUnavailable()
	}
	if len(ledger.Bindings) >= p.config.Bounds.MaxBindings || len(ledger.Receipts) >= p.config.Bounds.MaxBindings {
		return nil, NativePersonalProvisionReceipt{}, sourceUnavailable()
	}
	i := e.intent
	owner := SourceOwnerRef{e.candidate.RuntimeID, e.candidate.RootID, e.candidate.OwnerID}
	revision := sourceCommandKey([]interface{}{personalRegistryRevision(current), personalStablePayload(i), bindingRevision})
	r := NativePersonalProvisionReceipt{PersonalSourceRevision, i.CommandID, i.PrincipalID, i.Account, owner, bindingRevision, revision, i.EnrollmentSHA256, i.CommandSHA256, "applied"}
	ledger.Bindings[i.Account.AccountID] = core.PersonalBindingRecord{PrincipalID: i.PrincipalID, Account: i.Account, OwnerRef: owner, BindingRevision: bindingRevision, AccountRegistryRevision: actor.AccountRegistryRevision, Enrollment: i.Enrollment, OwnerKind: "new"}
	ledger.Receipts[personalReceiptKey(i.PrincipalID, i.Account.AccountID, i.CommandID)] = core.PersonalProvisionRecord{Payload: personalStablePayload(i), Receipt: r}
	ledger.Revision = revision
	return ledger, r, nil
}
func (s *Server) personalOverlayLedgerLocked() (*core.PersonalBindingLedger, error) {
	p := s.personalSource.Load()
	if p == nil {
		return s.forest.PersonalBindings, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	selected := s.forest.PersonalBindings
	count := 0
	for _, entry := range p.candidates {
		if entry.pending == nil || entry.scope == nil || entry.scope.pending != entry.pending || entry.ledger == nil {
			continue
		}
		count++
		if count > 1 || entry.write == nil || !entry.write.owns(p.coordinator) {
			return nil, sourceUnavailable()
		}
		selected = entry.ledger
	}
	return p.canonicalOverlayLedgerLocked(selected)
}
func (p *personalSource) publishPersonalLocked(scope *stagedScope, pending *stagedPending, stamp stagedDurableStamp) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var selected *personalProvisionEntry
	for _, entry := range p.candidates {
		if entry.scope != scope || entry.pending != pending {
			continue
		}
		if selected != nil {
			return sourceUnavailable()
		}
		selected = entry
	}
	if selected == nil || selected.ledger == nil || selected.write == nil || !selected.write.owns(p.coordinator) || stamp.Pair.Key != pending.key {
		return sourceUnavailable()
	}
	if p.server.forest.Children[pending.root.ID] != nil {
		return sourceDenied()
	}
	p.server.forest.Children[pending.root.ID] = pending.root
	p.server.forest.PersonalBindings = selected.ledger
	scope.pending, scope.configured, scope.reconciled = nil, true, true
	return nil
}
func (p *personalSource) personalPairWitnessLocked(e *personalProvisionEntry) error {
	if e.candidate.Receipt == nil {
		return sourceDenied()
	}
	scope := p.server.stagedScopes[personalScopeID(e.intent.Account.AccountID)]
	if scope == nil || !scope.reconciled || scope.pending != nil || scope.descriptor.Bounds != p.config.StagedBounds {
		return sourceDenied()
	}
	index, err := stagedForestIndex(p.server.forest)
	if err != nil {
		return sourceUnavailable()
	}
	root := index[scope.descriptor.Binding.RootID]
	if root == nil {
		return sourceDenied()
	}
	raw, present := root.CommandReceipts[personalReceiptKey(e.actor.PrincipalID, e.grant.Account.AccountID, e.candidate.CommandID)]
	var receipt stagedReceipt
	if !present || decodeStagedInternal(raw, &receipt) != nil {
		return sourceDenied()
	}
	command := personalStagedCommand(e.intent, scope.descriptor.Binding.ScopeID)
	if receipt.Command != command || receipt.Fingerprint != stagedCommandFingerprint(scope.descriptor.Binding, command) {
		return sourceDenied()
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return sourceUnavailable()
	}
	pair, err := stagedReceiptPair(scope.descriptor.Binding, stagedCommandKey(command), encoded)
	if err != nil {
		return sourceDenied()
	}
	p.server.stateWriter.mutex.Lock()
	defer p.server.stateWriter.mutex.Unlock()
	_, err = p.server.stateWriter.pairedStamp(p.server.statePath(), &pair)
	return err
}

func (p *personalSource) commitPersonalPending(e *personalProvisionEntry, actor sourceProvisionVerified, permit *sourceWritePermit) error {
	pair := e.snapshot.pairs[stagedPairKey(e.scope.descriptor.Binding.ScopeID, e.pending.key)]
	stamp, err := p.server.stateWriter.commitPaired(e.snapshot, pair)
	if err != nil {
		p.markPersonalUnknown(e, permit)
		return sourceUnavailable()
	}
	if err = p.server.publishOwnedPair(e.scope.descriptor.Binding.ScopeID, e.pending, stamp); err != nil {
		p.markPersonalUnknown(e, permit)
		return sourceUnavailable()
	}
	permit.finish(true, true)
	if err = p.completePersonalCommit(e, &stamp); err != nil {
		return err
	}
	if actor.ExpiresAt <= domainNow() {
		return sourceDenied()
	}
	return nil
}
