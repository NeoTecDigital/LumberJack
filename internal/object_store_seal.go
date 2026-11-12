// Written by Richard Christopher, Copyright 2026 Richard Christopher
package internal

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NeoTecDigital/LumberJack/internal/compat"
)

// Objects under an encrypted storage mode.
//
// THE DECISION: objects are SEALED, not refused. The state file in kms or local-test mode is never
// plaintext on the disk (secure_storage.go), and an object log beside it that was would hand the
// contents of every attachment to anyone holding the directory. Refusing object writes in those
// modes was the other correct answer; it was not taken because the object log is the storage the
// 10 MiB inline attachments are meant to grow out of, and an install that encrypts is exactly the
// install that needs it.
//
// WHAT IS SHARED with secure_storage.go: the key wrapper (KMS or the local-test file), storageSeal
// and storageOpen, and the shape sealResource uses — one random key per object, sealed under a
// master that the wrapper wraps, with the resource identity in the additional data. WHAT IS NOT: the
// per-snapshot re-keying and the per-account grant wraps. A snapshot is rewritten whole and can take
// a fresh master and fresh grants on every write; an object is appended once and never rewritten, so
// the master lives for the store and there is nothing to revoke a grant by rewriting. Read access to
// objects is decided by the route (api_objects.go), not by a per-user key.
//
// THE ID IS THE BLAKE3 OF THE PLAINTEXT, and it is in the clear in the record header. That is what
// content addressing means — the same bytes must have the same id in every store, sealed or not, or
// trees and commits could not name them. It also means the store discloses WHETHER it holds a given
// known file, which a sealed state file does not. That is inherent in the design and not a defect of
// this implementation.
//
// THE LABEL. A key file at version 1 seals under the legacy label, version 2 under the neutral one,
// and a record's flag says which label its payload was sealed under: flag 1 the key file's, flag 2
// the neutral one. Both are read forever; a store writes the flag its key file names
// (docs/extension-api.md §7.5).
//
// On the disk: `<name>.objects/key` holds the store id and the wrapped master. Each sealed payload is
//
//	[60] key      storageSeal(master, object key, aad "key/<id>")     — 12 nonce + 32 + 16 tag
//	[n+28] body   storageSeal(object key, plaintext, aad "object/<id>") — 12 nonce + n + 16 tag

const (
	objectKeyFileName    = "key"
	objectSealedKeySize  = 12 + 32 + 16
	objectSealedOverhead = objectSealedKeySize + 12 + 16
)

// objectKeyEnvelope is the key file. The id is random and in the clear, as the encrypted state
// envelope's is; it scopes the additional data so a key file cannot be moved under another store.
type objectKeyEnvelope struct {
	Version int               `json:"version"`
	ID      string            `json:"id"`
	Key     wrappedStorageKey `json:"key"`
}

// objectSealer holds a store's master. label is its key file's, and writeFlag the record flag new
// records are sealed under.
type objectSealer struct {
	id        string
	master    []byte
	label     compat.Label
	writeFlag byte
}

// objectSealerFor is the sealer of a key file version, or false for a version no build wrote.
func objectSealerFor(version int, id string) (*objectSealer, bool) {
	switch version {
	case compat.ObjectKeyFileLegacy:
		return &objectSealer{id: id, label: compat.LabelLegacy, writeFlag: objectSealed}, true
	case compat.ObjectKeyFileNeutral:
		return &objectSealer{id: id, label: compat.LabelNeutral, writeFlag: objectSealedNeutral}, true
	}
	return nil, false
}

func (s *objectSealer) aad(purpose string) []byte {
	return []byte(s.label.ObjectsPrefix() + s.id + "/" + purpose)
}

// recordAAD is the additional data of a record's payload: under the key file's label for flag 1,
// under the neutral label for flag 2.
func (s *objectSealer) recordAAD(flag byte, purpose string) []byte {
	if flag == objectSealedNeutral {
		return []byte(compat.LabelNeutral.ObjectsPrefix() + s.id + "/" + purpose)
	}
	return s.aad(purpose)
}

// seal is one object's payload under one fresh key, under the store's write flag.
func (s *objectSealer) seal(id objectID, plaintext []byte) ([]byte, error) {
	key, err := storageRandomKey()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	wrapped, err := storageSeal(s.master, key, s.recordAAD(s.writeFlag, "key/"+id.hex()))
	if err != nil {
		return nil, err
	}
	body, err := storageSeal(key, plaintext, s.recordAAD(s.writeFlag, "object/"+id.hex()))
	if err != nil {
		return nil, err
	}
	return append(wrapped, body...), nil
}

// open is the reverse. GCM authenticates both layers, so a payload that was altered, or that belongs
// to another id, fails here before the plaintext hash is ever consulted.
func (s *objectSealer) open(id objectID, flag byte, payload []byte) ([]byte, error) {
	if len(payload) < objectSealedOverhead {
		return nil, errors.New("sealed object payload is too short")
	}
	key, err := storageOpen(s.master, payload[:objectSealedKeySize], s.recordAAD(flag, "key/"+id.hex()))
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return storageOpen(key, payload[objectSealedKeySize:], s.recordAAD(flag, "object/"+id.hex()))
}

// openObjectSealer decides the store's mode from the disk and the configuration together, and
// REFUSES when they disagree — the same way file.go refuses a plaintext state file under an
// encrypted mode and an encrypted one without it. There is no object migration in either direction.
//
// A nil answer with a nil error is plaintext mode.
func openObjectSealer(dir string, storage *secureStorage, hasSegments bool) (*objectSealer, error) {
	path := filepath.Join(dir, objectKeyFileName)
	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		if storage == nil {
			return nil, nil
		}
		if hasSegments {
			return nil, errors.New("plaintext object store under encrypted storage: there is no object migration; move or remove the plaintext segments")
		}
		return createObjectSealer(dir, path, storage)
	case err != nil:
		return nil, fmt.Errorf("object store key: %w", err)
	}
	if storage == nil {
		return nil, errors.New("encrypted object store requires configured storage encryption")
	}
	var envelope objectKeyEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil || len(envelope.ID) != 64 {
		return nil, errors.New("unsupported object store key format")
	}
	sealer, known := objectSealerFor(envelope.Version, envelope.ID)
	if !known {
		return nil, errors.New("unsupported object store key format")
	}
	if storage.label == compat.LabelNeutral {
		// Neutral mode writes flag 2 even beside a version-1 key file, which is rewrapped only on an
		// explicit rewrap: its flag-1 records stay readable forever.
		sealer.writeFlag = objectSealedNeutral
	}
	sealer.master, err = storage.wrapper.Unwrap(context.Background(), envelope.Key, sealer.aad("master"))
	if err != nil {
		return nil, fmt.Errorf("object store key: %w", err)
	}
	return sealer, nil
}

// createObjectSealer mints a store's master, wraps it, and publishes the key file the way the state
// file is published: written whole, synced, renamed into place, directory synced.
func createObjectSealer(dir, path string, storage *secureStorage) (*objectSealer, error) {
	id, err := storageRandomKey()
	if err != nil {
		return nil, err
	}
	master, err := storageRandomKey()
	if err != nil {
		return nil, err
	}
	version := compat.ObjectKeyFileLegacy
	if storage.label == compat.LabelNeutral {
		version = compat.ObjectKeyFileNeutral
	}
	sealer, _ := objectSealerFor(version, hex.EncodeToString(id))
	sealer.master = master
	wrapped, err := storage.wrapper.Wrap(context.Background(), master, sealer.aad("master"))
	if err != nil {
		return nil, fmt.Errorf("object store key: %w", err)
	}
	encoded, err := json.Marshal(objectKeyEnvelope{Version: version, ID: sealer.id, Key: wrapped})
	if err != nil {
		return nil, err
	}
	if err := publishFile(dir, path, encoded); err != nil {
		return nil, fmt.Errorf("object store key: %w", err)
	}
	return sealer, nil
}

// publishFile writes data to path durably: a temporary file, synced, renamed over the name, and the
// directory synced. It is the discipline of publishState for a file that is not the state.
func publishFile(dir, path string, data []byte) error {
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, objectFileMode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}
