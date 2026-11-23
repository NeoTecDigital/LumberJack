// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/NeoTecDigital/LumberJack/internal/persist"
	"github.com/NeoTecDigital/LumberJack/types"
)

const banner = "LUMBERJACK-RECORD-1\nresident command journal\n"

type marker struct {
	Indexes    []Index `json:"indexes,omitempty"`
	Store      string  `json:"store"`
	Owner      string  `json:"owner"`
	ReceiptKey []byte  `json:"receipt_key"`
}

// A journal is also the fault boundary: after an ambiguous write only recovered,
// independently synced frames may authorize publication.
type journal interface {
	Stage([]byte) uint64
	Commit(uint64) error
	Close() error
	Abandon()
	Segments() []string
}

type Store struct {
	key    *journalKey
	leases cursorCache
	path   string
	m      marker
	s      *state
	log    journal
	mu     sync.RWMutex
	fault  error
	life   sync.RWMutex
	closed bool
	queue  chan *request
	done   chan struct{}
}

func Open(path, issuer string) (*Store, error) {
	return OpenIndexed(path, issuer, nil, false)
}
func OpenIndexed(path, issuer string, decls []Index, reader bool) (*Store, error) {
	return OpenWithStorage(path, issuer, decls, reader, nil)
}
func OpenWithStorage(path, issuer string, decls []Index, reader bool, cfg *types.StorageConfig) (*Store, error) {
	if cfg != nil {
		if cfg.Mode == "" || cfg.MigrateLegacy || cfg.RewrapKeys || cfg.Validate() != nil {
			return nil, types.ErrSealingLabel
		}
	}
	defs, err := normalized(decls)
	if err != nil {
		return nil, err
	}
	if !ValidPrincipal(issuer) {
		return nil, ErrInvalid
	}
	m, key, err := readMarker(path, issuer, defs, reader, cfg)
	if err != nil {
		return nil, err
	}
	if !reader && m.Owner != issuer {
		return nil, ErrDenied
	}
	if !slices.Equal(m.Indexes, defs) {
		return nil, ErrConflict
	}
	log, rs, err := openLog(path, 0)
	if err != nil {
		return nil, err
	}
	s := &Store{key: key, path: path, m: m, s: empty(), log: log, queue: make(chan *request, 64), done: make(chan struct{})}
	s.s.defs = m.Indexes
	if err = s.replay(rs); err != nil {
		log.Abandon()
		return nil, err
	}
	if !s.canOpen(issuer, reader) {
		log.Abandon()
		return nil, ErrDenied
	}
	go s.writer()
	return s, nil
}
func openLog(path string, covered uint64) (*persist.Log, []persist.Record, error) {
	cfg := types.DefaultPersistence()
	cfg.Mode = types.PersistenceTiered
	cfg.HotSync = types.HotSyncCommit
	log, rs, err := persist.Open(path, cfg, persist.NoHook{}, covered)
	if err != nil {
		return nil, nil, err
	}
	// A prior process may have died after append and before fsync. Confirm even a
	// retained prefix (or truncation) before reporting any recovered receipt.
	for _, p := range log.Segments() {
		if err = syncPath(p); err != nil {
			log.Abandon()
			return nil, nil, err
		}
	}
	if err = syncPath(filepath.Dir(path)); err != nil {
		log.Abandon()
		return nil, nil, err
	}
	return log, rs, nil
}
func syncPath(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func readMarker(path, issuer string, defs []Index, reader bool, cfg *types.StorageConfig) (marker, *journalKey, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) && !reader {
		return createMarker(path, issuer, defs, cfg)
	}
	if errors.Is(err, os.ErrNotExist) {
		return marker{}, nil, ErrDenied
	}
	if err != nil {
		return marker{}, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 131073))
	if err != nil {
		return marker{}, nil, err
	}
	if len(data) > 131072 || (bytes.HasPrefix(data, []byte(banner)) && len(data) > 65536) {
		return marker{}, nil, ErrInvalid
	}
	m, key, err := decodeMarker(data, cfg)
	if err == nil && (!semanticID(m.Store) || !token(m.Owner) || len(m.ReceiptKey) != 32) {
		err = ErrInvalid
	}
	return m, key, err
}

// Verify the actual wrapper, not just its pathname, before reusing a resident handle.
func (s *Store) VerifyPolicy(cfg *types.StorageConfig) error {
	if cfg == nil && s.key == nil {
		return nil
	}
	if (cfg == nil) != (s.key == nil) {
		return types.ErrSealingLabel
	}
	m, k, e := readMarker(s.path, "", nil, true, cfg)
	if e != nil || k == nil || !bytes.Equal(k.key, s.key.key) || m.Store != s.m.Store {
		return types.ErrSealingLabel
	}
	return nil
}
func createMarker(path, issuer string, defs []Index, cfg *types.StorageConfig) (marker, *journalKey, error) {
	var m marker
	segs, err := filepath.Glob(path + ".log.*")
	if err != nil || len(segs) != 0 {
		return m, nil, ErrConflict
	}
	var salt [32]byte
	if _, err = rand.Read(salt[:]); err != nil {
		return m, nil, err
	}
	m = marker{Indexes: defs, Store: hex.EncodeToString(salt[:]), Owner: issuer, ReceiptKey: make([]byte, 32)}
	if _, err = rand.Read(m.ReceiptKey); err != nil {
		return m, nil, err
	}
	raw, key, err := markerBytes(m, cfg)
	if err != nil {
		return m, nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".record-format-*")
	if err != nil {
		return m, nil, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return m, nil, err
	}
	if ce != nil {
		return m, nil, ce
	}
	if err = os.Link(f.Name(), path); err != nil {
		return m, nil, err
	}
	return m, key, syncPath(filepath.Dir(path))
}
func (s *Store) replay(rs []persist.Record) error {
	for _, r := range rs {
		var f frame
		raw, err := s.key.frame(false, r.Seq, r.Body)
		if err != nil {
			return err
		}
		if err := Decode(raw, &f); err != nil {
			return err
		}
		if f.Store != s.m.Store || f.Issuer != s.m.Owner || f.Sequence != r.Seq {
			return ErrInvalid
		}
		if _, _, err := s.s.run(&f); err != nil {
			return fmt.Errorf("frame %d: %w", r.Seq, err)
		}
	}
	return nil
}
func (s *Store) Close() error {
	s.life.Lock()
	defer s.life.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.queue)
	<-s.done
	if s.fault != nil {
		return s.fault
	}
	return s.log.Close()
}

func (s *Store) canOpen(issuer string, reader bool) bool {
	return issuer == s.m.Owner || reader && len(s.s.grants[issuer]) != 0
}
func (s *Store) MatchOpen(issuer string, defs []Index, reader bool) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.canOpen(issuer, reader) {
		return ErrDenied
	}
	clean, e := normalized(defs)
	if e != nil {
		return e
	}
	if !slices.Equal(clean, s.m.Indexes) {
		return ErrConflict
	}
	return nil
}

// MarkerOwner authenticates an existing marker without opening its log, taking a lease or writing.
func MarkerOwner(path string, cfg *types.StorageConfig) (string, error) {
	m, _, e := readMarker(path, "", nil, true, cfg)
	return m.Owner, e
}
