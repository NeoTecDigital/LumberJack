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

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

const encryptedStateMagic = "LUMBERJACK-ENCRYPTED-STATE-3\n"

type storageAccountKey struct {
	key     []byte
	wrapped wrappedStorageKey
}
type secureStorage struct {
	wrapper  storageKeyWrapper
	id       string
	accounts map[string]storageAccountKey
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
	return []byte("momentum/storage/v3/" + s.id + "/" + purpose)
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

// The immutable flat snapshot is decoded outside the forest lock. Its own graph
// supplies effective permissions; no live map is consulted during network I/O.
func (s *secureStorage) encode(data []byte) ([]byte, error) {
	ctx := context.Background()
	forest, err := decodeState(data)
	if err != nil {
		return nil, err
	}
	var flat stateDocument
	if err = json.Unmarshal(data, &flat); err != nil {
		return nil, err
	}
	master, err := storageRandomKey()
	if err != nil {
		return nil, err
	}
	defer clear(master)
	document := encryptedStateDocument{Root: flat.Root, Accounts: map[string]wrappedStorageKey{}, Nodes: map[string]encryptedResource{}, Conversations: map[string]encryptedConversation{}}
	for id, node := range flat.Nodes {
		// Root is backend security state: it must not acquire a user's grant merely
		// because that user administers account inventory. Conversations are separate.
		users := []string{}
		if id != flat.Root {
			for _, account := range forest.Users {
				if node.CheckPermission(account.ID, core.ReadPermission) {
					users = append(users, account.ID)
				}
			}
		}
		body, err := json.Marshal(node)
		if err != nil {
			return nil, err
		}
		if id == flat.Root {
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(body, &fields); err != nil {
				return nil, err
			}
			delete(fields, "conversations")
			body, err = json.Marshal(fields)
			if err != nil {
				return nil, err
			}
		}
		encrypted, err := s.sealResource(ctx, master, "node/"+id, body, users)
		if err != nil {
			return nil, err
		}
		document.Nodes[id] = encrypted
	}
	for id, conversation := range forest.Conversations {
		if conversation == nil {
			return nil, errors.New("cannot encrypt missing conversation")
		}
		header := *conversation
		header.Messages = nil
		body, err := json.Marshal(header)
		if err != nil {
			return nil, err
		}
		users := []string{}
		for userID, member := range header.Members {
			if !member.Invited {
				users = append(users, userID)
			}
		}
		encrypted, err := s.sealResource(ctx, master, "conversation/"+id, body, users)
		if err != nil {
			return nil, err
		}
		saved := encryptedConversation{Header: encrypted, Messages: map[string]encryptedResource{}, Order: []string{}}
		for _, message := range conversation.Messages {
			users = nil
			for userID, member := range header.Members {
				if !member.Invited && message.Sequence > member.From {
					users = append(users, userID)
				}
			}
			body, err = json.Marshal(message)
			if err != nil {
				return nil, err
			}
			if _, duplicate := saved.Messages[message.ID]; duplicate {
				return nil, errors.New("duplicate encrypted conversation message")
			}
			saved.Messages[message.ID], err = s.sealResource(ctx, master, "message/"+id+"/"+message.ID, body, users)
			if err != nil {
				return nil, err
			}
			saved.Order = append(saved.Order, message.ID)
		}
		document.Conversations[id] = saved
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
	return json.Marshal(encryptedStateEnvelope{Version: 3, ID: s.id, Key: wrapped, Payload: payload})
}

func (s *secureStorage) decode(data []byte) ([]byte, error) {
	var envelope encryptedStateEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, errors.New("invalid encrypted state envelope")
	}
	if envelope.Version != 3 || len(envelope.ID) != 64 {
		return nil, errors.New("unsupported encrypted state format")
	}
	s.id = envelope.ID
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
		var node nodeRecord
		if err = json.Unmarshal(body, &node); err != nil || node.Node == nil || node.ID != id {
			return nil, errors.New("encrypted node identity mismatch")
		}
		flat.Nodes[id] = &node
	}
	root := flat.Nodes[flat.Root]
	if root == nil {
		return nil, errors.New("encrypted state root is missing")
	}
	if len(document.Conversations) > 0 {
		root.Conversations = map[string]*core.Conversation{}
	}
	for id, saved := range document.Conversations {
		body, err := s.openResource(master, "conversation/"+id, saved.Header)
		if err != nil {
			return nil, err
		}
		var conversation core.Conversation
		if err = json.Unmarshal(body, &conversation); err != nil || conversation.ID != id {
			return nil, errors.New("encrypted conversation identity mismatch")
		}
		for _, messageID := range saved.Order {
			body, err = s.openResource(master, "message/"+id+"/"+messageID, saved.Messages[messageID])
			if err != nil {
				return nil, err
			}
			var message core.ConversationMessage
			if err = json.Unmarshal(body, &message); err != nil || message.ID != messageID {
				return nil, errors.New("encrypted message identity mismatch")
			}
			conversation.Messages = append(conversation.Messages, message)
		}
		root.Conversations[id] = &conversation
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
	sealed, err := storage.encode(data)
	if err != nil {
		return nil, true, fmt.Errorf("encrypted storage write refused: %w", err)
	}
	return append([]byte(encryptedStateMagic), sealed...), true, nil
}
