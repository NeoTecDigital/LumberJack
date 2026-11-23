// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package store

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"
	"os"
	"path/filepath"

	"github.com/NeoTecDigital/LumberJack/internal/persist"
	"github.com/NeoTecDigital/LumberJack/types"
)

type inventory struct {
	marker marker
	frames []persist.Record
	digest [32]byte
}

func hashPart(h hash.Hash, b []byte) {
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(b))))
	h.Write(b)
}
func recordInventory(path string, cfg *types.StorageConfig, owner string) (inventory, error) {
	var out inventory
	m, k, e := readMarker(path, "", nil, true, cfg)
	if e != nil {
		return out, e
	}
	if m.Owner != owner {
		return out, ErrDenied
	}
	frames, e := persist.Inspect(path)
	if e != nil {
		return out, e
	}
	s := Store{m: m, s: empty(), key: k}
	s.s.defs = m.Indexes
	if e = s.replay(frames); e != nil {
		return out, e
	}
	h := sha256.New()
	b, e := json.Marshal(m)
	if e != nil {
		return out, e
	}
	hashPart(h, b)
	for i := range frames {
		f := &frames[i]
		f.Body, e = k.frame(false, f.Seq, f.Body)
		if e != nil {
			return out, e
		}
		hashPart(h, f.Body)
	}
	out.marker = m
	out.frames = frames
	copy(out.digest[:], h.Sum(nil))
	return out, nil
}

// SealJournal operates only inside a disposable stage. The publisher, not this routine,
// owns the live directory exchange. Never recover a damaged input or regenerate receipts.
func SealJournal(path, owner string, cfg *types.StorageConfig, already bool) error {
	if cfg == nil || cfg.Mode == "" {
		return types.ErrSealingLabel
	}
	if already {
		_, e := recordInventory(path, cfg, owner)
		return e
	}
	original, e := recordInventory(path, nil, owner)
	if e != nil {
		return e
	}
	temp, e := os.MkdirTemp(filepath.Dir(path), ".journal-seal-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	target := filepath.Join(temp, filepath.Base(path))
	raw, k, e := markerBytes(original.marker, cfg)
	if e != nil {
		return e
	}
	if e = os.WriteFile(target, raw, 0600); e != nil {
		return e
	}
	if e = writeFrames(target, k, original.frames); e != nil {
		return e
	}
	verified, e := recordInventory(target, cfg, owner)
	if e != nil {
		return e
	}
	if verified.digest != original.digest {
		return errors.New("record conversion digest mismatch")
	}
	segments, e := filepath.Glob(path + ".log.*")
	if e != nil {
		return e
	}
	for _, p := range segments {
		if e = os.Remove(p); e != nil {
			return e
		}
	}
	files, e := os.ReadDir(temp)
	if e != nil {
		return e
	}
	for _, f := range files {
		if e = os.Rename(filepath.Join(temp, f.Name()), filepath.Join(filepath.Dir(path), f.Name())); e != nil {
			return e
		}
	}
	return nil
}
func writeFrames(path string, k *journalKey, frames []persist.Record) error {
	log, _, e := openLog(path, 0)
	if e != nil {
		return e
	}
	defer log.Abandon()
	for _, f := range frames {
		b, err := k.frame(true, f.Seq, f.Body)
		if err != nil {
			return err
		}
		if seq := log.Stage(b); seq != f.Seq {
			return ErrConflict
		}
		if err = log.Commit(f.Seq); err != nil {
			return err
		}
	}
	return log.Close()
}
