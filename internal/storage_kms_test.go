// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStorageKMSIdentityIntegrityAndRefusals(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	ciphertext := []byte("opaque-kms-ciphertext")
	corrupt := false
	unavailable := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if r.Header.Get("Metadata-Flavor") != "Google" {
				t.Error("missing metadata protection")
			}
			w.Header().Set("Metadata-Flavor", "Google")
			json.NewEncoder(w).Encode(map[string]string{"access_token": "test-identity", "token_type": "Bearer"})
			return
		}
		if unavailable {
			w.WriteHeader(503)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-identity" {
			t.Error("missing service identity")
		}
		var request map[string]string
		json.NewDecoder(r.Body).Decode(&request)
		if request["additionalAuthenticatedDataCrc32c"] != storageCRC([]byte("scope")) {
			t.Error("AAD integrity omitted")
		}
		if strings.HasSuffix(r.URL.Path, ":encrypt") {
			checksum := storageCRC(ciphertext)
			if corrupt {
				checksum = "0"
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"ciphertext": base64.StdEncoding.EncodeToString(ciphertext), "ciphertextCrc32c": checksum, "verifiedPlaintextCrc32c": true, "verifiedAdditionalAuthenticatedDataCrc32c": true})
		} else {
			json.NewEncoder(w).Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString(key), "plaintextCrc32c": storageCRC(key)})
		}
	}))
	defer server.Close()
	wrapper := newKMSStorageWrapper("projects/test/locations/us/keyRings/test/cryptoKeys/storage")
	wrapper.endpoint = server.URL + "/"
	wrapper.metadata = server.URL + "/token"
	wrapped, err := wrapper.Wrap(context.Background(), key, []byte("scope"))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := wrapper.Unwrap(context.Background(), wrapped, []byte("scope"))
	if err != nil || !bytes.Equal(key, recovered) {
		t.Fatalf("KMS roundtrip: %v", err)
	}
	corrupt = true
	if _, err = wrapper.Wrap(context.Background(), key, []byte("scope")); err == nil {
		t.Fatal("KMS integrity mismatch accepted")
	}
	corrupt = false
	unavailable = true
	if _, err = wrapper.Wrap(context.Background(), key, []byte("scope")); err == nil {
		t.Fatal("KMS outage accepted")
	}
	wrapped.Key = "projects/other/locations/us/keyRings/test/cryptoKeys/storage"
	if _, err = wrapper.Unwrap(context.Background(), wrapped, []byte("scope")); err == nil {
		t.Fatal("untrusted stored key resource accepted")
	}
}
