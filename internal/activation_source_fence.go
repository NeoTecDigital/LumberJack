// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// One coordinator belongs to the actual Server, not a principal or adapter.
// Permits are acquired BEFORE forestMutex and held through durable publication.
type sourceCoordinator struct {
	mu                sync.Mutex
	changed           chan struct{}
	writer            *sourceWritePermit
	readers           map[*sourceReadPermit]bool
	generation        uint64
	sessionGeneration uint64
	unknown           bool
	sessions          map[sourceSessionKey]*sourceSession
	limit             int
	timeout           time.Duration
	required          bool
	legacyRunning     int
}
type sourceWritePermit struct {
	coordinator *sourceCoordinator
	key         string
	active      bool
	running     bool
}
type sourceReadPermit struct {
	coordinator *sourceCoordinator
	borrowed    *sourceWritePermit
	generation  uint64
	active      bool
}

func (s *Server) sourceFence() *sourceCoordinator {
	if held := s.sourceCoordinator.Load(); held != nil {
		return held
	}
	created := &sourceCoordinator{changed: make(chan struct{}), readers: map[*sourceReadPermit]bool{}, sessions: map[sourceSessionKey]*sourceSession{}}
	if s.sourceCoordinator.CompareAndSwap(nil, created) {
		return created
	}
	return s.sourceCoordinator.Load()
}
func (c *sourceCoordinator) signalLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}
func (c *sourceCoordinator) beginWrite(ctx context.Context, key string) (*sourceWritePermit, error) {
	c.mu.Lock()
	timeout := c.timeout
	c.mu.Unlock()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	for {
		c.mu.Lock()
		permit, changed, err := c.tryWriterLocked(key)
		c.mu.Unlock()
		if permit != nil || err != nil {
			return permit, err
		}
		select {
		case <-ctx.Done():
			return nil, sourceUnavailable()
		case <-changed:
		}
	}
}
func (c *sourceCoordinator) tryWriterLocked(key string) (*sourceWritePermit, chan struct{}, error) {
	if key == "" {
		return nil, nil, sourceInvalid()
	}
	if c.required && c.legacyRunning != 0 {
		return nil, c.changed, nil
	}
	if c.unknown {
		if c.writer == nil || c.writer.key != key || c.writer.running {
			return nil, nil, sourceUnavailable()
		}
		c.writer.running = true
		return c.writer, nil, nil
	}
	if c.writer != nil || len(c.readers) != 0 {
		return nil, c.changed, nil
	}
	p := &sourceWritePermit{c, key, true, true}
	c.writer = p
	return p, nil, nil
}

func (s *Server) enrollmentSourceCommand(d *domainEngine, entry *domainEntry) stagedCommand {
	actor := entry.enrollment.actor
	binding := DomainNativeBinding{ScopeID: enrollmentScopeID(actor.Scope.AccountID)}
	if owned, present := d.lookupDomainScope(actor.Scope); present {
		binding = owned.Binding
	}
	return enrollmentCommand(actor, binding)
}

// A recovery key comes only from exact current native pending/receipt history.
// Looking it up neither scans other principals nor authenticates an actor.
func (s *Server) sourceRecoveryPermit(scopeID, key string) (*sourceWritePermit, error) {
	s.forestMutex.RLock()
	command, err := s.sourceRecoveryCommandLocked(scopeID, key)
	s.forestMutex.RUnlock()
	if err != nil {
		return nil, err
	}
	return s.sourceFence().beginWrite(context.Background(), sourceCommandKey(command))
}
func (s *Server) sourceRecoveryCommandLocked(scopeID, key string) (stagedCommand, error) {
	scope := s.stagedScopes[scopeID]
	if scope == nil {
		return stagedCommand{}, sourceUnavailable()
	}
	if scope.pending != nil {
		if scope.pending.key != key {
			return stagedCommand{}, sourceUnavailable()
		}
		return scope.pending.receipt.Command, nil
	}
	index, err := stagedForestIndex(s.forest)
	if err != nil || index[scope.descriptor.Binding.RootID] == nil {
		return stagedCommand{}, sourceUnavailable()
	}
	stored, present := index[scope.descriptor.Binding.RootID].CommandReceipts[key]
	var receipt stagedReceipt
	if !present || decodeStagedInternal(stored, &receipt) != nil || stagedCommandKey(receipt.Command) != key {
		return stagedCommand{}, sourceUnavailable()
	}
	return receipt.Command, nil
}
func (c *sourceCoordinator) beginRead(borrow *sourceWritePermit) (*sourceReadPermit, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.unknown || c.legacyRunning != 0 || (c.writer != nil && c.writer != borrow) {
		return nil, sourceUnavailable()
	}
	if borrow != nil && (borrow != c.writer || !borrow.active) {
		return nil, sourceDenied()
	}
	p := &sourceReadPermit{c, borrow, c.generation, true}
	c.readers[p] = true
	return p, nil
}
func (p *sourceReadPermit) recheck() error {
	c := p.coordinator
	c.mu.Lock()
	defer c.mu.Unlock()
	if !p.active || !c.readers[p] || c.unknown || p.generation != c.generation {
		return sourceUnavailable()
	}
	if p.borrowed != nil && (c.writer != p.borrowed || !p.borrowed.active) {
		return sourceUnavailable()
	}
	return nil
}
func (p *sourceReadPermit) release() {
	c := p.coordinator
	c.mu.Lock()
	delete(c.readers, p)
	p.active = false
	c.signalLocked()
	c.mu.Unlock()
}

// Unknown never releases a writer into a clean evidence generation. Recovery
// must supply the SAME actual permit and a storage witness, not a disposition.
func (p *sourceWritePermit) finish(known bool, changed bool) {
	c := p.coordinator
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writer != p || !p.active {
		return
	}
	if !known {
		c.unknown = true
		p.running = false
		c.generation++
		c.signalLocked()
		return
	}
	if changed {
		c.generation++
	}
	c.unknown, p.active, p.running, c.writer = false, false, false, nil
	c.signalLocked()
}
func (p *sourceWritePermit) owns(c *sourceCoordinator) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return p != nil && p.coordinator == c && p.active && c.writer == p
}
func (p *sourceWritePermit) noEffect(unchanged bool) {
	c := p.coordinator
	c.mu.Lock()
	unknown := c.unknown
	c.mu.Unlock()
	p.finish(unchanged && !unknown, false)
}
func sourceCommandKey(value interface{}) string {
	raw, err := CanonicalDomainJSON(value)
	if err != nil {
		return ""
	}
	return stagedHash(raw)
}

// Whole private persisted graph, not workRevision or UI path/filter state.
func (s *Server) sourceForestRevision() string {
	s.forestMutex.RLock()
	defer s.forestMutex.RUnlock()
	return s.sourceForestRevisionLocked()
}
func (s *Server) sourceForestRevisionLocked() string {
	raw, err := encodeState(s.forest)
	if err != nil {
		return ""
	}
	return stagedHash(raw)
}

// An unknown result is not fixed by a cache hit or historical permission. This
// reads/fsyncs unchanged exact bytes on the SAME selected protected store only.
func (s *Server) inspectSourcePair(ctx context.Context, snapshot stateSnapshot, pair stagedPair) (*sourceStorageWitness, error) {
	p := s.personalSource.Load()
	if p == nil || snapshot.path != s.statePath() || snapshot.seq == 0 {
		return nil, sourceUnavailable()
	}
	writer := s.stateWriter
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	if writer.flushing || ctx.Err() != nil {
		return nil, sourceUnavailable()
	}
	file, dir, err := sourceWitnessFiles(snapshot.path)
	if err != nil {
		return nil, err
	}
	witness := &sourceStorageWitness{file: file, dir: dir, path: snapshot.path}
	ok := false
	defer func() {
		if !ok {
			witness.close()
		}
	}()
	data, err := s.sourceWitnessPayload(file, p.config.StagedBounds.MaxSnapshotBytes)
	if err != nil || ctx.Err() != nil || stagedHash(data) != hex.EncodeToString(snapshot.hash) {
		return nil, sourceUnavailable()
	}
	pairs, err := stagedPairsFromBytes(data)
	if err != nil || !matchingStagedPair(pairs, pair) || !equalStagedPairs(snapshot.pairs, pairs) {
		return nil, sourceUnavailable()
	}
	if !sourceFileIdentity(file, snapshot.path) || !sourceFileIdentity(dir, filepath.Dir(snapshot.path)) || file.Sync() != nil || dir.Sync() != nil || ctx.Err() != nil {
		return nil, sourceUnavailable()
	}
	if !sourceFileIdentity(file, snapshot.path) || !sourceFileIdentity(dir, filepath.Dir(snapshot.path)) {
		return nil, sourceUnavailable()
	}
	writer.durableSeq, writer.durableHash, writer.durablePath, writer.durablePairs = snapshot.seq, append([]byte(nil), snapshot.hash...), snapshot.path, pairs
	witness.stamp, err = writer.pairedStamp(snapshot.path, &pair)
	if err != nil {
		return nil, sourceUnavailable()
	}
	ok = true
	return witness, nil
}
func sourceWitnessFiles(path string) (*os.File, *os.File, error) {
	canonical, err := filepath.Abs(path)
	if err != nil || canonical != path || filepath.Clean(path) != path {
		return nil, nil, sourceUnavailable()
	}
	directory := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return nil, nil, sourceUnavailable()
	}
	dfd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, sourceUnavailable()
	}
	dir := os.NewFile(uintptr(dfd), directory)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		dir.Close()
		return nil, nil, sourceUnavailable()
	}
	file := os.NewFile(uintptr(fd), path)
	fi, e1 := file.Stat()
	di, e2 := dir.Stat()
	if e1 != nil || e2 != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 || !di.IsDir() || di.Mode().Perm() != 0700 || !sourceFileIdentity(file, path) {
		file.Close()
		dir.Close()
		return nil, nil, sourceUnavailable()
	}
	return file, dir, nil
}
func sourceFileIdentity(file *os.File, path string) bool {
	opened, err := file.Stat()
	if err != nil {
		return false
	}
	current, err := os.Lstat(path)
	return err == nil && current.Mode()&os.ModeSymlink == 0 && os.SameFile(opened, current)
}
func (s *Server) sourceWitnessPayload(file *os.File, limit int) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > int64(limit) {
		return nil, sourceUnavailable()
	}
	storage, err := s.storageCodec()
	if err != nil {
		return nil, sourceUnavailable()
	}
	if storage != nil {
		raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
		if err != nil || len(raw) > limit || !bytes.HasPrefix(raw, []byte(encryptedStateMagic)) {
			return nil, sourceUnavailable()
		}
		clone := &secureStorage{wrapper: storage.wrapper, id: storage.id, accounts: map[string]storageAccountKey{}}
		body, err := clone.decode(raw[len(encryptedStateMagic):])
		if err != nil || len(body) > limit {
			return nil, sourceUnavailable()
		}
		return body, nil
	}
	banner := make([]byte, len(stateMagic))
	hash := make([]byte, sha256.Size)
	if _, err = io.ReadFull(file, banner); err != nil || !isStateBanner(banner) {
		return nil, sourceUnavailable()
	}
	if _, err = io.ReadFull(file, hash); err != nil {
		return nil, sourceUnavailable()
	}
	body, err := readCappedGzip(file, min(int64(limit), int64(maxDecompressedState)))
	if err != nil || stagedHash(body) != hex.EncodeToString(hash) {
		return nil, sourceUnavailable()
	}
	return body, nil
}

// Recovery publishes already-durable facts only, never fresh authority/effects.
func (p *personalSource) recoverPersonalWitness(ctx context.Context, e *personalProvisionEntry) error {
	p.mu.Lock()
	if e.state != "unknown" {
		p.mu.Unlock()
		return nil
	}
	pending, scope, original, snapshot := e.pending, e.scope, e.write, e.snapshot
	if e.recovering || pending == nil || scope == nil || original == nil {
		p.mu.Unlock()
		return sourceUnavailable()
	}
	e.recovering = true
	p.mu.Unlock()
	defer p.finishPersonalRecovery(e)
	permit, err := p.coordinator.beginWrite(ctx, sourceCommandKey(pending.receipt.Command))
	if err != nil {
		return err
	}
	pair := snapshot.pairs[stagedPairKey(scope.descriptor.Binding.ScopeID, pending.key)]
	witness, err := p.server.inspectSourcePair(ctx, snapshot, pair)
	if err != nil {
		permit.finish(false, false)
		return sourceUnavailable()
	}
	defer witness.close()
	if !p.recoveryStillOwned(ctx, e, pending, scope, original) || !witness.current() {
		permit.finish(false, false)
		return sourceUnavailable()
	}
	if err = p.server.publishOwnedPair(scope.descriptor.Binding.ScopeID, pending, witness.stamp); err != nil {
		permit.finish(false, false)
		return sourceUnavailable()
	}
	permit.finish(true, true)
	return p.completePersonalCommit(e, &witness.stamp)
}
func (p *personalSource) finishPersonalRecovery(e *personalProvisionEntry) {
	p.mu.Lock()
	e.recovering = false
	p.mu.Unlock()
}
func (p *personalSource) recoveryStillOwned(ctx context.Context, e *personalProvisionEntry, pending *stagedPending, scope *stagedScope, permit *sourceWritePermit) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Expired/closing attempts can publish witnessed facts for cleanup ONLY.
	// personalLiveLocked and fresh Core callbacks still prohibit disclosure.
	return ctx.Err() == nil && p.server.personalSource.Load() == p && e.state == "unknown" && e.pending == pending && e.scope == scope && e.write == permit && permit.owns(p.coordinator)
}

type sourceStorageWitness struct {
	stamp     stagedDurableStamp
	file, dir *os.File
	path      string
}

func (w *sourceStorageWitness) close() { w.file.Close(); w.dir.Close() }
func (w *sourceStorageWitness) current() bool {
	return sourceFileIdentity(w.file, w.path) && sourceFileIdentity(w.dir, filepath.Dir(w.path))
}
