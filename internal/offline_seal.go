// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/types"
	"io"
	"os"
	"path/filepath"
)

// SealHubCopy is private to the offline publisher. It receives a private copy, never a live
// directory. A hot-log/replicated hub needs its own cutover; never leave its frames plain.
func SealHubCopy(dir, name string, cfg types.StorageConfig, already bool) error {
	path := filepath.Join(dir, name+".dat")
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		switch f.Name() {
		case name + ".dat", name + ".dat.lock", name + ".objects":
		default:
			return errors.New("unsupported file in offline hub")
		}
	}
	cfg.MigrateLegacy = !already
	s := &Server{config: types.ServerConfig{Storage: &cfg}, logger: types.NewLogger(), stateWriter: newStateWriter(nil)}
	before, level, e := offlineForest(s, path, already)
	if e != nil {
		return e
	}
	codec, e := s.storageCodec()
	if e != nil {
		return e
	}
	if !already {
		envelope, e := codec.encodeAt(before, level)
		if e != nil {
			return e
		}
		if e = os.WriteFile(path, append([]byte(encryptedStateMagic), envelope...), 0600); e != nil {
			return e
		}
		// Read using a fresh codec, not the writer's cached account keys.
		cfg.MigrateLegacy = false
		reader := &Server{config: types.ServerConfig{Storage: &cfg}, logger: types.NewLogger(), stateWriter: newStateWriter(nil)}
		after, _, e := offlineForest(reader, path, true)
		if e != nil {
			return e
		}
		if sha256.Sum256(before) != sha256.Sum256(after) {
			return errors.New("hub forest conversion digest mismatch")
		}
	}
	return sealObjectCopy(filepath.Join(dir, name+".objects"), codec, already)
}

func offlineForest(s *Server, path string, sealed bool) ([]byte, int, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, 0, e
	}
	defer f.Close()
	header := make([]byte, len(encryptedStateMagic))
	if _, e = io.ReadFull(f, header); e != nil {
		return nil, 0, e
	}
	if bytes.Equal(header, []byte(encryptedStateMagic)) != sealed {
		return nil, 0, types.ErrSealingLabel
	}
	if _, e = f.Seek(0, 0); e != nil {
		return nil, 0, e
	}
	level := 0
	if !sealed {
		level, e = stateMagicLevel(f)
		if e != nil || level == 0 {
			return nil, 0, errors.New("unsupported hub format")
		}
		if _, e = f.Seek(0, 0); e != nil {
			return nil, 0, e
		}
	}
	t, e := s.readState(f)
	if e != nil {
		return nil, 0, e
	}
	if t.LogSequence != 0 {
		return nil, 0, errors.New("tiered hub requires separate cutover")
	}
	forest, e := linkTable(t)
	if e != nil {
		return nil, 0, e
	}
	b, e := encodeState(forest)
	return b, level, e
}

func checkedObjects(path string, codec *secureStorage) (*objectStore, error) {
	entries, e := os.ReadDir(path)
	if e != nil {
		return nil, e
	}
	for _, f := range entries {
		if f.Name() == objectKeyFileName && codec != nil {
			continue
		}
		var number uint32
		if _, e := fmt.Sscanf(f.Name(), "%08d"+objectSegmentExt, &number); e != nil || number == 0 || f.Name() != fmt.Sprintf("%08d%s", number, objectSegmentExt) {
			return nil, errors.New("unknown object store file")
		}
	}
	s, e := openObjectStore(path, DefaultMaxObjectBytes, codec)
	if e != nil {
		return nil, e
	}
	if len(s.repairs) > 0 {
		s.close()
		return nil, errors.New("object store requires recovery before seal")
	}
	return s, nil
}
func sealObjectCopy(path string, codec *secureStorage, already bool) error {
	if _, e := os.Lstat(path); errors.Is(e, os.ErrNotExist) {
		return nil
	}
	var inputCodec *secureStorage
	if already {
		inputCodec = codec
	}
	src, e := checkedObjects(path, inputCodec)
	if e != nil {
		return e
	}
	defer src.close()
	if already {
		for id := range src.index {
			if _, e = src.get(id); e != nil {
				return e
			}
		}
		return nil
	}
	dest, e := os.MkdirTemp(filepath.Dir(path), ".sealed-objects-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dest)
	dst, e := openObjectStore(dest, DefaultMaxObjectBytes, codec)
	if e != nil {
		return e
	}
	for id := range src.index {
		b, e := src.get(id)
		if e == nil {
			_, e = dst.put(b)
		}
		if e != nil {
			dst.close()
			return e
		}
	}
	dst.close()
	check, e := checkedObjects(dest, codec)
	if e != nil {
		return e
	}
	defer check.close()
	if len(src.index) != len(check.index) {
		return errors.New("object inventory mismatch")
	}
	for id := range src.index {
		if _, e = check.get(id); e != nil {
			return e
		}
	} // get verifies the content digest against id.
	if e = os.RemoveAll(path); e != nil {
		return e
	}
	return os.Rename(dest, path)
}
