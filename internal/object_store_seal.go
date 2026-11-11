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
// On the disk: `<name>.objects/key` holds the store id and the wrapped master. Each sealed payload is
//
//	[60] key      storageSeal(master, object key, aad "key/<id>")     — 12 nonce + 32 + 16 tag
//	[n+28] body   storageSeal(object key, plaintext, aad "object/<id>") — 12 nonce + n + 16 tag

const (
	objectKeyFileName     = "key"
	objectSealedKeySize   = 12 + 32 + 16
	objectSealedOverhead  = objectSealedKeySize + 12 + 16
	objectKeyFileVersion  = 1
	objectSealerAADPrefix = "momentum/objects/v1/"
)

// objectKeyEnvelope is the key file. The id is random and in the clear, as the encrypted state
// envelope's is; it scopes the additional data so a key file cannot be moved under another store.
type objectKeyEnvelope struct {
	Version int               `json:"version"`
	ID      string            `json:"id"`
	Key     wrappedStorageKey `json:"key"`
}

type objectSealer struct {
	id     string
	master []byte
}

func (s *objectSealer) aad(purpose string) []byte {
	return []byte(objectSealerAADPrefix + s.id + "/" + purpose)
}

// seal is one object's payload under one fresh key.
func (s *objectSealer) seal(id objectID, plaintext []byte) ([]byte, error) {
	key, err := storageRandomKey()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	wrapped, err := storageSeal(s.master, key, s.aad("key/"+id.hex()))
	if err != nil {
		return nil, err
	}
	body, err := storageSeal(key, plaintext, s.aad("object/"+id.hex()))
	if err != nil {
		return nil, err
	}
	return append(wrapped, body...), nil
}

// open is the reverse. GCM authenticates both layers, so a payload that was altered, or that belongs
// to another id, fails here before the plaintext hash is ever consulted.
func (s *objectSealer) open(id objectID, payload []byte) ([]byte, error) {
	if len(payload) < objectSealedOverhead {
		return nil, errors.New("sealed object payload is too short")
	}
	key, err := storageOpen(s.master, payload[:objectSealedKeySize], s.aad("key/"+id.hex()))
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return storageOpen(key, payload[objectSealedKeySize:], s.aad("object/"+id.hex()))
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
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.Version != objectKeyFileVersion || len(envelope.ID) != 64 {
		return nil, errors.New("unsupported object store key format")
	}
	sealer := &objectSealer{id: envelope.ID}
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
	sealer := &objectSealer{id: hex.EncodeToString(id), master: master}
	wrapped, err := storage.wrapper.Wrap(context.Background(), master, sealer.aad("master"))
	if err != nil {
		return nil, fmt.Errorf("object store key: %w", err)
	}
	encoded, err := json.Marshal(objectKeyEnvelope{Version: objectKeyFileVersion, ID: sealer.id, Key: wrapped})
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
