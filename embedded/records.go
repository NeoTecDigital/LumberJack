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
	store *store.Store
	lock  *os.File
	path  string
	refs  int
}

var recordMu sync.Mutex
var recordRuntimes = map[string]*recordRuntime{}

// RecordHandle binds the trusted embedding host's authenticated principal at open.
// Only the owner writes. Indexed read grants belong to this store, not a legacy profile.
type RecordHandle struct {
	mu     sync.RWMutex
	rt     *recordRuntime
	issuer string
	reader bool
}

func OpenRecords(dir, name, principal string) (*RecordHandle, error) {
	return OpenIndexedRecords(dir, name, principal, nil, false)
}

type RecordIndex = store.Index

func OpenIndexedRecords(dir, name, principal string, defs []RecordIndex, reader bool) (*RecordHandle, error) {
	if !filepath.IsAbs(dir) || name == "" || len(name) > 128 || name == "." || name == ".." || strings.ContainsAny(name, "/\\*?[]") || !store.ValidPrincipal(principal) {
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
	if reader {
		if _, err := os.Stat(filepath.Join(dir, name+".dat")); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, store.ErrDenied
			}
			return nil, err
		}
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
		if err := rt.store.MatchOpen(principal, defs, reader); err != nil {
			return nil, err
		}
		rt.refs++
		return &RecordHandle{rt: rt, issuer: principal, reader: reader}, nil
	}
	lock, err := acquireProfileLock(path, recordProfile)
	if err != nil {
		return nil, err
	}
	s, err := store.OpenIndexed(path, principal, defs, reader)
	if err != nil {
		releaseLock(lock)
		return nil, err
	}
	rt := &recordRuntime{store: s, lock: lock, path: path, refs: 1}
	recordRuntimes[path] = rt
	return &RecordHandle{rt: rt, issuer: principal, reader: reader}, nil
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
			p.Settle(extension.Outcome{State: extension.WriteUnknown, Err: store.ErrUnavailable})
		}
		return nil, store.ErrUnavailable
	}
	if h.reader {
		if p != nil {
			p.Settle(extension.Outcome{State: extension.WriteRefused, Unchanged: p.WantsRevision(), Err: store.ErrDenied})
		}
		return nil, store.ErrDenied
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

// IndexedPage reads from the ordered index seam; a continuation rechecks live authority.
func (h *RecordHandle) IndexedPage(raw []byte) ([]byte, error) {
	var q store.IndexPage
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
	return h.rt.store.IndexedPage(h.issuer, q)
}
