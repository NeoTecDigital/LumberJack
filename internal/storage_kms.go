// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Service identity comes from the fixed GCE metadata endpoint. No service-account
// private key or OAuth token is persisted; redirects never forward credentials.
type kmsStorageWrapper struct {
	name     string
	client   *http.Client
	endpoint string
	metadata string
}

func newKMSStorageWrapper(name string) *kmsStorageWrapper {
	return &kmsStorageWrapper{name: name, client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, endpoint: "https://cloudkms.googleapis.com/v1/", metadata: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}
}
func storageCRC(data []byte) string {
	return strconv.FormatUint(uint64(crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))), 10)
}
func (w *kmsStorageWrapper) token(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.metadata, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	response, err := w.client.Do(req)
	if err != nil {
		return "", errors.New("KMS service identity unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Metadata-Flavor") != "Google" {
		return "", errors.New("KMS service identity unavailable")
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&token); err != nil || token.AccessToken == "" || token.TokenType != "Bearer" {
		return "", errors.New("invalid KMS service identity response")
	}
	return token.AccessToken, nil
}
func (w *kmsStorageWrapper) call(ctx context.Context, operation string, payload map[string]string) (map[string]json.RawMessage, error) {
	token, err := w.token(ctx)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.endpoint+w.name+":"+operation, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := w.client.Do(req)
	if err != nil {
		return nil, errors.New("KMS request unavailable")
	}
	defer response.Body.Close()
	// Never include an upstream body: it can contain key material or echoed inputs.
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("KMS %s refused (HTTP %d)", operation, response.StatusCode)
	}
	var result map[string]json.RawMessage
	if err = json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result); err != nil {
		return nil, errors.New("invalid KMS response")
	}
	return result, nil
}
func kmsString(values map[string]json.RawMessage, name string) string {
	var s string
	_ = json.Unmarshal(values[name], &s)
	return s
}
func kmsVerified(values map[string]json.RawMessage, name string) bool {
	var b bool
	_ = json.Unmarshal(values[name], &b)
	return b
}
func (w *kmsStorageWrapper) Wrap(ctx context.Context, key, aad []byte) (wrappedStorageKey, error) {
	result, err := w.call(ctx, "encrypt", map[string]string{"plaintext": base64.StdEncoding.EncodeToString(key), "additionalAuthenticatedData": base64.StdEncoding.EncodeToString(aad), "plaintextCrc32c": storageCRC(key), "additionalAuthenticatedDataCrc32c": storageCRC(aad)})
	if err != nil {
		return wrappedStorageKey{}, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(kmsString(result, "ciphertext"))
	if err != nil || len(ciphertext) == 0 || !kmsVerified(result, "verifiedPlaintextCrc32c") || !kmsVerified(result, "verifiedAdditionalAuthenticatedDataCrc32c") || storageCRC(ciphertext) != kmsString(result, "ciphertextCrc32c") {
		return wrappedStorageKey{}, errors.New("KMS encryption integrity check failed")
	}
	return wrappedStorageKey{Key: w.name, Ciphertext: ciphertext}, nil
}
func (w *kmsStorageWrapper) Unwrap(ctx context.Context, key wrappedStorageKey, aad []byte) ([]byte, error) {
	// A stored file cannot redirect this service's OAuth bearer to another host/key.
	if key.Key != w.name {
		return nil, errors.New("encrypted state names a different KMS key")
	}
	result, err := w.call(ctx, "decrypt", map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(key.Ciphertext), "additionalAuthenticatedData": base64.StdEncoding.EncodeToString(aad), "ciphertextCrc32c": storageCRC(key.Ciphertext), "additionalAuthenticatedDataCrc32c": storageCRC(aad)})
	if err != nil {
		return nil, err
	}
	plaintext, err := base64.StdEncoding.DecodeString(kmsString(result, "plaintext"))
	if err != nil || len(plaintext) != 32 || storageCRC(plaintext) != kmsString(result, "plaintextCrc32c") {
		return nil, errors.New("KMS decryption integrity check failed")
	}
	return plaintext, nil
}
