// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/internal/compat"
	"github.com/NeoTecDigital/LumberJack/internal/slots"
)

const encryptedStateMagic = "LUMBERJACK-ENCRYPTED-STATE-3\n"

// The envelope version does for an encrypted file what stateMagicReferences does for a plain one: a
// build from before references refuses any version but 3 and so cannot open a forest holding one.
// The version also names the sealing label (compat.Label): 3 and 4 are the legacy label, 5 and 6 the
// neutral one, and the cut build refuses 5 and 6 (docs/extension-api.md §7.5).

type storageAccountKey struct {
	key     []byte
	wrapped wrappedStorageKey
}

// secureStorage seals one store. label is the one its envelope was read under, and the one it is
// written under: legacy for a new store in this release, so a store keeps the label it has. level
// is the state level its envelope version carried at the last decode.
type secureStorage struct {
	wrapper  storageKeyWrapper
	id       string
	accounts map[string]storageAccountKey
	label    compat.Label
	level    int
}
type encryptedStateEnvelope struct {
	Version int               `json:"version"`
	ID      string            `json:"id"`
	Key     wrappedStorageKey `json:"key"`
	Payload []byte            `json:"payload"`
}
type encryptedResource struct {
	Payload     []byte            `json:"payload"`
	BackendKey  []byte            `json:"backend_key"`
	AccountKeys map[string][]byte `json:"account_keys"`
}
type encryptedConversation struct {
	Header   encryptedResource            `json:"header"`
	Messages map[string]encryptedResource `json:"messages"`
	Order    []string                     `json:"order"`
}
type encryptedStateDocument struct {
	Root          string                           `json:"root"`
	Accounts      map[string]wrappedStorageKey     `json:"accounts"`
	Nodes         map[string]encryptedResource     `json:"nodes"`
	Conversations map[string]encryptedConversation `json:"conversations"`
}

func (server *Server) storageCodec() (*secureStorage, error) {
	server.storageOnce.Do(func() {
		wrapper, err := storageWrapperFromEnvironment()
		server.storageErr = err
		if err != nil || wrapper == nil {
			return
		}
		id, err := storageRandomKey()
		if err != nil {
			server.storageErr = err
			return
		}
		server.storage = &secureStorage{wrapper: wrapper, id: hex.EncodeToString(id), accounts: map[string]storageAccountKey{}}
	})
	return server.storage, server.storageErr
}
func (s *secureStorage) aad(purpose string) []byte {
	return []byte(s.label.StatePrefix() + s.id + "/" + purpose)
}

// relabel makes the store write under another label from its next write on. Every account key it
// holds is opened under the label it was wrapped under and wrapped again under the new one — one
// wrap per account — so the next envelope carries them all under one label (docs/extension-api.md
// §7.5). A failure leaves the store on its old label.
func (s *secureStorage) relabel(ctx context.Context, label compat.Label) error {
	if label == s.label {
		return nil
	}
	opened := make(map[string]storageAccountKey, len(s.accounts))
	for id := range s.accounts {
		key, err := s.accountKey(ctx, id)
		if err != nil {
			return err
		}
		opened[id] = storageAccountKey{key: key}
	}
	previous := s.label
	s.label = label
	for id, account := range opened {
		wrapped, err := s.wrapper.Wrap(ctx, account.key, s.aad("account/"+id))
		if err != nil {
			s.label = previous
			return err
		}
		account.wrapped = wrapped
		opened[id] = account
	}
	s.accounts = opened
	return nil
}

func (s *secureStorage) accountKey(ctx context.Context, id string) ([]byte, error) {
	account, exists := s.accounts[id]
	if exists && len(account.key) == 32 {
		return account.key, nil
	}
	var err error
	if exists {
		account.key, err = s.wrapper.Unwrap(ctx, account.wrapped, s.aad("account/"+id))
	} else {
		account.key, err = storageRandomKey()
		if err == nil {
			account.wrapped, err = s.wrapper.Wrap(ctx, account.key, s.aad("account/"+id))
		}
	}
	if err != nil {
		return nil, err
	}
	s.accounts[id] = account
	return account.key, nil
}
func (s *secureStorage) sealResource(ctx context.Context, master []byte, id string, plaintext []byte, users []string) (encryptedResource, error) {
	result := encryptedResource{AccountKeys: map[string][]byte{}}
	key, err := storageRandomKey()
	if err != nil {
		return result, err
	}
	defer clear(key)
	result.Payload, err = storageSeal(key, plaintext, s.aad("resource/"+id))
	if err != nil {
		return result, err
	}
	result.BackendKey, err = storageSeal(master, key, s.aad("backend/"+id))
	if err != nil {
		return result, err
	}
	for _, userID := range users {
		account, err := s.accountKey(ctx, userID)
		if err != nil {
			return result, err
		}
		result.AccountKeys[userID], err = storageSeal(account, key, s.aad("grant/"+id+"/"+userID))
		if err != nil {
			return result, err
		}
	}
	return result, nil
}
func (s *secureStorage) openResource(master []byte, id string, resource encryptedResource) ([]byte, error) {
	key, err := storageOpen(master, resource.BackendKey, s.aad("backend/"+id))
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return storageOpen(key, resource.Payload, s.aad("resource/"+id))
}

// encode seals a plaintext document at the level the document itself requires.
func (s *secureStorage) encode(data []byte) ([]byte, error) {
	return s.encodeAt(data, stateLevelFor(data))
}

// encodeAt seals a plaintext document under the store's label at a state level.
//
// The immutable flat snapshot is decoded outside the forest lock. Its own graph
// supplies effective permissions; no live map is consulted during network I/O. Each node is sealed
// as the bytes the document holds for it, never re-encoded from a decode, so its numbers are the
// literals it was written with.
func (s *secureStorage) encodeAt(data []byte, level int) ([]byte, error) {
	ctx := context.Background()
	table, err := decodeTable(data)
	if err != nil {
		return nil, err
	}
	forest, err := linkTable(table)
	if err != nil {
		return nil, err
	}
	master, err := storageRandomKey()
	if err != nil {
		return nil, err
	}
	defer clear(master)
	document := encryptedStateDocument{Root: table.Root, Accounts: map[string]wrappedStorageKey{}, Nodes: map[string]encryptedResource{}, Conversations: map[string]encryptedConversation{}}
	for id, record := range table.records {
		// Root is backend security state: it must not acquire a user's grant merely
		// because that user administers account inventory. Conversations are separate.
		users := []string{}
		if id != table.Root {
			for _, account := range forest.Users {
				if record.Node.CheckPermission(account.ID, core.ReadPermission) {
					users = append(users, account.ID)
				}
			}
		}
		// The root's record is sealed whole, its "conversations" slot inside it: the backend key
		// opens it, and no account is granted the root (owner decision Q4(a)).
		encrypted, err := s.sealResource(ctx, master, "node/"+id, []byte(table.Nodes[id]), users)
		if err != nil {
			return nil, err
		}
		document.Nodes[id] = encrypted
	}
	// Persist only extant accounts; revocation creates new resource keys on every
	// snapshot and removes old grant wraps. Downloaded copies cannot be recalled.
	for _, account := range forest.Users {
		if key, exists := s.accounts[account.ID]; exists {
			document.Accounts[account.ID] = key.wrapped
		}
	}
	inner, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	var compressed bytes.Buffer
	compressor := gzip.NewWriter(&compressed)
	if _, err = compressor.Write(inner); err != nil {
		return nil, err
	}
	if err = compressor.Close(); err != nil {
		return nil, err
	}
	wrapped, err := s.wrapper.Wrap(ctx, master, s.aad("snapshot"))
	if err != nil {
		return nil, err
	}
	payload, err := storageSeal(master, compressed.Bytes(), s.aad("snapshot"))
	if err != nil {
		return nil, err
	}
	return json.Marshal(encryptedStateEnvelope{Version: s.label.EnvelopeVersion(level), ID: s.id, Key: wrapped, Payload: payload})
}

func (s *secureStorage) decode(data []byte) ([]byte, error) {
	var envelope encryptedStateEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, errors.New("invalid encrypted state envelope")
	}
	label, level, known := compat.EnvelopeLabel(envelope.Version)
	if !known || len(envelope.ID) != 64 {
		return nil, errors.New("unsupported encrypted state format")
	}
	s.id, s.label, s.level = envelope.ID, label, level
	master, err := s.wrapper.Unwrap(context.Background(), envelope.Key, s.aad("snapshot"))
	if err != nil {
		return nil, err
	}
	defer clear(master)
	compressed, err := storageOpen(master, envelope.Payload, s.aad("snapshot"))
	if err != nil {
		return nil, err
	}
	inner, err := readCappedGzip(bytes.NewReader(compressed), maxDecompressedState)
	if err != nil {
		return nil, err
	}
	var document encryptedStateDocument
	if err = json.Unmarshal(inner, &document); err != nil {
		return nil, errors.New("invalid encrypted state document")
	}
	flat := stateDocument{Version: stateVersion, Root: document.Root, Nodes: map[string]*nodeRecord{}}
	for id, resource := range document.Nodes {
		body, err := s.openResource(master, "node/"+id, resource)
		if err != nil {
			return nil, err
		}
		node, children, err := core.DecodeRecord(body)
		if err != nil || node.ID != id {
			return nil, errors.New("encrypted node identity mismatch")
		}
		flat.Nodes[id] = &nodeRecord{Node: node, Children: children}
	}
	root := flat.Nodes[flat.Root]
	if root == nil {
		return nil, errors.New("encrypted state root is missing")
	}
	if len(document.Conversations) > 0 {
		conversations, err := s.openConversations(master, document.Conversations)
		if err != nil {
			return nil, err
		}
		root.Node.Slots(slots.Token{}).SetRaw("conversations", conversations)
	}
	s.accounts = map[string]storageAccountKey{}
	for id, key := range document.Accounts {
		s.accounts[id] = storageAccountKey{wrapped: key}
	}
	return json.Marshal(flat)
}

func (server *Server) readEncryptedState(file *os.File) (*core.Node, bool, error) {
	banner := make([]byte, len(encryptedStateMagic))
	_, err := io.ReadFull(file, banner)
	encrypted := err == nil && string(banner) == encryptedStateMagic
	if !encrypted {
		_, err = file.Seek(0, io.SeekStart)
		return nil, false, err
	}
	storage, err := server.storageCodec()
	if err != nil {
		return nil, true, err
	}
	if storage == nil {
		return nil, true, errors.New("encrypted state requires configured storage encryption")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDecompressedState+1))
	if err != nil {
		return nil, true, err
	}
	if len(data) > maxDecompressedState {
		return nil, true, errors.New("encrypted state exceeds size limit")
	}
	data, err = storage.decode(data)
	if err != nil {
		return nil, true, err
	}
	server.raiseStateLevel(storage.level)
	forest, err := decodeState(data)
	if err != nil {
		return nil, true, err
	}
	if os.Getenv("CORRESPONDER_STORAGE_REWRAP_KEYS") == "1" {
		for id, key := range storage.accounts {
			raw, err := storage.accountKey(context.Background(), id)
			if err != nil {
				return nil, true, err
			}
			key.key = raw
			key.wrapped, err = storage.wrapper.Wrap(context.Background(), raw, storage.aad("account/"+id))
			if err != nil {
				return nil, true, err
			}
			storage.accounts[id] = key
		}
		server.storageRewrite = true
	}
	return forest, true, nil
}

func (server *Server) prepareEncryptedState(data []byte) ([]byte, bool, error) {
	storage, err := server.storageCodec()
	if err != nil {
		return nil, false, err
	}
	if storage == nil {
		return nil, false, nil
	}
	sealed, err := storage.encodeAt(data, server.raiseStateLevel(stateLevelFor(data)))
	if err != nil {
		return nil, true, fmt.Errorf("encrypted storage write refused: %w", err)
	}
	return append([]byte(encryptedStateMagic), sealed...), true, nil
}
