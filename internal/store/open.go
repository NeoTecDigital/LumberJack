// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	defs, err := normalized(decls)
	if err != nil {
		return nil, err
	}
	if !ValidPrincipal(issuer) {
		return nil, ErrInvalid
	}
	m, err := readMarker(path, issuer, defs, reader)
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
	s := &Store{path: path, m: m, s: empty(), log: log, queue: make(chan *request, 64), done: make(chan struct{})}
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
func readMarker(path, issuer string, defs []Index, reader bool) (marker, error) {
	var m marker
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		if reader {
			return m, ErrDenied
		}
		return createMarker(path, issuer, defs)
	}
	if err != nil {
		return m, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return m, err
	}
	if len(b) > 65536 || !strings.HasPrefix(string(b), banner) {
		return m, fmt.Errorf("%w: not a record profile", ErrConflict)
	}
	err = Decode(b[len(banner):], &m)
	if err == nil && (!semanticID(m.Store) || !token(m.Owner) || len(m.ReceiptKey) != 32) {
		err = ErrInvalid
	}
	return m, err
}
func createMarker(path, issuer string, defs []Index) (marker, error) {
	var m marker
	// Never adopt an orphaned journal or attach it to another principal.
	segs, err := filepath.Glob(path + ".log.*")
	if err != nil || len(segs) != 0 {
		return m, ErrConflict
	}
	var salt [32]byte
	if _, err = rand.Read(salt[:]); err != nil {
		return m, err
	}
	m = marker{Indexes: defs, Store: hex.EncodeToString(salt[:]), Owner: issuer, ReceiptKey: make([]byte, 32)}
	if _, err = rand.Read(m.ReceiptKey); err != nil {
		return m, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return m, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".record-format-*")
	if err != nil {
		return m, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append([]byte(banner), raw...)); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return m, err
	}
	if ce != nil {
		return m, ce
	}
	if err = os.Link(f.Name(), path); err != nil {
		return m, err
	}
	return m, syncPath(filepath.Dir(path))
}
func (s *Store) replay(rs []persist.Record) error {
	for _, r := range rs {
		var f frame
		if err := Decode(r.Body, &f); err != nil {
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
