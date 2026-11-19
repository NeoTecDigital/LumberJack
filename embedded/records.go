// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/internal/store"
	"github.com/NeoTecDigital/LumberJack/types"
)

type recordRuntime struct {
	store       *store.Store
	lock        *os.File
	owner, path string
	refs        int
}

var recordMu sync.Mutex
var recordRuntimes = map[string]*recordRuntime{}

// RecordHandle binds the trusted embedding host's authenticated principal at open.
// This version exposes only a single-owner local-sync profile, not legacy grants.
type RecordHandle struct {
	mu     sync.RWMutex
	rt     *recordRuntime
	issuer string
}

func OpenRecords(dir, name, principal string) (*RecordHandle, error) {
	if !filepath.IsAbs(dir) || name == "" || len(name) > 128 || name == "." || name == ".." || strings.ContainsAny(name, "/\\*?[]") || principal == "" {
		return nil, store.ErrInvalid
	}
	cfg, _ := types.StorageFromEnvironment()
	if cfg.Mode != "" || cfg.MigrateLegacy || cfg.RewrapKeys {
		return nil, store.ErrDenied
	}
	// Do not silently open an encrypted, replicated or differently configured store.
	if _, err := os.Stat(filepath.Join(dir, types.StoreConfigFile)); err == nil || !errors.Is(err, os.ErrNotExist) {
		return nil, store.ErrConflict
	}
	if err := os.MkdirAll(dir, types.DataDirMode); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(real, name+".dat")
	recordMu.Lock()
	defer recordMu.Unlock()
	if rt := recordRuntimes[path]; rt != nil {
		if rt.owner != principal {
			return nil, store.ErrDenied
		}
		rt.refs++
		return &RecordHandle{rt: rt, issuer: principal}, nil
	}
	lock, err := acquireLock(path)
	if err != nil {
		return nil, err
	}
	s, err := store.Open(path, principal)
	if err != nil {
		releaseLock(lock)
		return nil, err
	}
	rt := &recordRuntime{s, lock, principal, path, 1}
	recordRuntimes[path] = rt
	return &RecordHandle{rt: rt, issuer: principal}, nil
}
func (h *RecordHandle) Apply(raw []byte) ([]byte, error) { return h.ApplyPermitted(raw, nil) }

// ApplyPermitted takes responsibility for one already-acquired permit. It settles
// after publication/reconciliation; the callback never runs under a store lock.
func (h *RecordHandle) ApplyPermitted(raw []byte, p extension.Permit) ([]byte, error) {
	h.mu.RLock()
	rt := h.rt
	h.mu.RUnlock()
	if rt == nil {
		if p != nil {
			p.Settle(extension.Outcome{State: extension.WriteRefused, Unchanged: true, Err: store.ErrUnavailable})
		}
		return nil, store.ErrUnavailable
	}
	r, err := rt.store.Apply(h.issuer, raw, p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(r)
}
func (h *RecordHandle) Page(raw []byte) ([]byte, error) {
	var q store.PageRequest
	if len(raw) > store.MaxBytes {
		return nil, store.ErrInvalid
	}
	if err := store.Decode(raw, &q); err != nil {
		return nil, err
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.rt == nil {
		return nil, store.ErrUnavailable
	}
	return h.rt.store.Page(h.issuer, q)
}
func (h *RecordHandle) Close() error {
	h.mu.Lock()
	rt := h.rt
	h.rt = nil
	h.mu.Unlock()
	if rt == nil {
		return nil
	}
	recordMu.Lock()
	defer recordMu.Unlock()
	rt.refs--
	if rt.refs > 0 {
		return nil
	}
	delete(recordRuntimes, rt.path)
	return errors.Join(rt.store.Close(), releaseLock(rt.lock))
}
