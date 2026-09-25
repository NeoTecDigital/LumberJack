// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
)

type wrappedStorageKey struct {
	Key        string `json:"key"`
	Ciphertext []byte `json:"ciphertext"`
}
type storageKeyWrapper interface {
	Wrap(context.Context, []byte, []byte) (wrappedStorageKey, error)
	Unwrap(context.Context, wrappedStorageKey, []byte) ([]byte, error)
}

// GCM generates a fresh random nonce for every key and content encryption. The
// resource identity and format version are authenticated as additional data.
func storageSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}
func storageOpen(key, sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("invalid encrypted storage payload")
	}
	result, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
	if err != nil {
		return nil, errors.New("encrypted storage authentication failed")
	}
	return result, nil
}
func storageRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

// localStorageWrapper is deliberately available only under local-test. It is
// for disposable isolated fixtures, never an automatic KMS outage fallback.
type localStorageWrapper struct{ key []byte }

func (w *localStorageWrapper) Wrap(_ context.Context, key, aad []byte) (wrappedStorageKey, error) {
	ciphertext, err := storageSeal(w.key, key, aad)
	return wrappedStorageKey{Key: "local-test/v1", Ciphertext: ciphertext}, err
}
func (w *localStorageWrapper) Unwrap(_ context.Context, key wrappedStorageKey, aad []byte) ([]byte, error) {
	if key.Key != "local-test/v1" {
		return nil, errors.New("storage key wrapper does not match")
	}
	return storageOpen(w.key, key.Ciphertext, aad)
}

func storageWrapperFromEnvironment() (storageKeyWrapper, error) {
	switch os.Getenv("CORRESPONDER_STORAGE_MODE") {
	case "":
		return nil, nil // Generic Lumberjack library compatibility; Momentum requires a mode.
	case "kms":
		name := os.Getenv("CORRESPONDER_STORAGE_KMS_KEY")
		if !validKMSKeyName(name) {
			return nil, errors.New("set CORRESPONDER_STORAGE_KMS_KEY to a Cloud KMS symmetric CryptoKey resource")
		}
		return newKMSStorageWrapper(name), nil
	case "local-test":
		path := os.Getenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE")
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("local-test storage key is unavailable: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
			return nil, errors.New("local-test storage key must be a private 32-byte file")
		}
		key, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return &localStorageWrapper{key: key}, nil
	default:
		return nil, errors.New("unsupported CORRESPONDER_STORAGE_MODE; use kms or explicit local-test")
	}
}
func validKMSKeyName(name string) bool {
	parts := strings.Split(name, "/")
	if len(parts) != 8 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" || parts[6] != "cryptoKeys" {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.ContainsAny(part, "?&#%\\\r\n") || part == "." || part == ".." {
			return false
		}
	}
	return true
}
