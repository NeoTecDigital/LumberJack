// Written by Richard Christopher, Copyright 2026 Richard Christopher
package internal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The object routes over the real router: who may reach them, what they refuse, what they answer, and
// the one thing they must never do — rewrite the state file.

// objectRequest builds a request for the object routes carrying a bearer, or none when bearer is "".
func objectRequest(method, target, bearer string, body []byte) *http.Request {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	return request
}

// putObject posts bytes through the router and decodes the receipt.
func putObject(t *testing.T, server *Server, bearer string, body []byte) (objectReceipt, *httptest.ResponseRecorder) {
	t.Helper()
	recorder := serve(t, server, objectRequest("POST", "/objects", bearer, body))
	var receipt objectReceipt
	if recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &receipt); err != nil {
			t.Fatalf("decode receipt %q: %v", recorder.Body.String(), err)
		}
	}
	return receipt, recorder
}

// stateFingerprint is the state file as it is on the disk: its modification time and its hash.
func stateFingerprint(t *testing.T, path string) (time.Time, [sha256.Size]byte) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return info.ModTime(), sha256.Sum256(data)
}

// A put, a get and a head over the router, and `.dat` untouched by all three.
func TestObjectRoutesRoundTripWithoutRewritingTheStateFile(t *testing.T) {
	server, _ := newStockServer(t)
	admin := sessionFor(t, server, adminID(t, server), "admin")
	statePath := server.statePath()
	modBefore, hashBefore := stateFingerprint(t, statePath)
	time.Sleep(20 * time.Millisecond) // so a rewrite could not hide behind mtime granularity

	body := randomBytes(t, 11<<20)
	receipt, recorder := putObject(t, server, admin, body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /objects: %d %s", recorder.Code, recorder.Body.String())
	}
	if receipt.Existed || receipt.Size != int64(len(body)) || len(receipt.ID) != 64 {
		t.Fatalf("receipt %+v", receipt)
	}
	if again, _ := putObject(t, server, admin, body); !again.Existed || again.ID != receipt.ID {
		t.Fatalf("second put: %+v, want existed", again)
	}

	got := serve(t, server, objectRequest("GET", "/objects/"+receipt.ID, admin, nil))
	if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), body) {
		t.Fatalf("GET /objects/{id}: %d, %d bytes back", got.Code, got.Body.Len())
	}
	if got.Header().Get("Content-Type") != "application/octet-stream" || got.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("GET headers: %v", got.Header())
	}

	head := serve(t, server, objectRequest("HEAD", "/objects/"+receipt.ID, admin, nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Fatalf("HEAD /objects/{id}: %d, %d body bytes, headers %v", head.Code, head.Body.Len(), head.Header())
	}

	modAfter, hashAfter := stateFingerprint(t, statePath)
	if !modAfter.Equal(modBefore) || hashAfter != hashBefore {
		t.Fatalf("the state file was rewritten by object writes: mtime %v -> %v", modBefore, modAfter)
	}
	if _, err := os.Stat(ObjectsPath(server.config)); err != nil {
		t.Fatalf("the object directory is not beside the state file: %v", err)
	}
}

// Every object route is behind the session guard, and behind the root's permission: no token is 401,
// a reader may read and not write, an unknown id is 404 and a malformed one is 400.
func TestObjectRoutesRequireASessionAndRootPermission(t *testing.T) {
	server, _ := newStockServer(t)
	admin := sessionFor(t, server, adminID(t, server), "admin")
	reader := sessionFor(t, server, addReadUser(t, server, "reader"), "reader")
	receipt, _ := putObject(t, server, admin, []byte("held"))

	for _, method := range []string{"GET", "HEAD"} {
		if code := serve(t, server, objectRequest(method, "/objects/"+receipt.ID, "", nil)).Code; code != http.StatusUnauthorized {
			t.Fatalf("anonymous %s: %d, want 401", method, code)
		}
	}
	if code := serve(t, server, objectRequest("POST", "/objects", "", []byte("x"))).Code; code != http.StatusUnauthorized {
		t.Fatalf("anonymous POST: %d, want 401", code)
	}

	if _, recorder := putObject(t, server, reader, []byte("not yours to write")); recorder.Code != http.StatusForbidden {
		t.Fatalf("reader POST /objects: %d, want 403", recorder.Code)
	}
	if got := serve(t, server, objectRequest("GET", "/objects/"+receipt.ID, reader, nil)); got.Code != http.StatusOK || got.Body.String() != "held" {
		t.Fatalf("reader GET: %d %q, want the bytes", got.Code, got.Body.String())
	}

	unknown := strings.Repeat("ab", 32)
	if code := serve(t, server, objectRequest("GET", "/objects/"+unknown, admin, nil)).Code; code != http.StatusNotFound {
		t.Fatalf("GET of an unknown id: %d, want 404", code)
	}
	if code := serve(t, server, objectRequest("HEAD", "/objects/"+unknown, admin, nil)).Code; code != http.StatusNotFound {
		t.Fatalf("HEAD of an unknown id: %d, want 404", code)
	}
	if code := serve(t, server, objectRequest("GET", "/objects/not-an-id", admin, nil)).Code; code != http.StatusBadRequest {
		t.Fatalf("GET of a malformed id: %d, want 400", code)
	}
}

// The cap is configurable, named in the refusal, and an object exactly at it is accepted.
func TestObjectRoutesRefuseOverTheConfiguredCap(t *testing.T) {
	server, _ := newStockServer(t)
	server.config.Process.MaxObjectBytes = 4096
	admin := sessionFor(t, server, adminID(t, server), "admin")

	if _, recorder := putObject(t, server, admin, randomBytes(t, 4097)); recorder.Code != http.StatusRequestEntityTooLarge || !strings.Contains(recorder.Body.String(), "4096") {
		t.Fatalf("POST over the cap: %d %q, want 413 naming the cap", recorder.Code, recorder.Body.String())
	}
	if _, recorder := putObject(t, server, admin, randomBytes(t, 4096)); recorder.Code != http.StatusOK {
		t.Fatalf("POST at the cap: %d %s", recorder.Code, recorder.Body.String())
	}
}

// Under an encrypted storage mode objects are SEALED: the plaintext is nowhere in the segment, the
// store reopens under the same key, a different key cannot open it, and a plaintext store cannot be
// adopted by an encrypted mode.
func TestObjectsAreSealedUnderEncryptedStorage(t *testing.T) {
	keyPath := storageTestKey(t)
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", keyPath)
	config := coreConfig()
	config.Process.DatabasePath = t.TempDir()

	server, err := NewCore(config)
	if err != nil {
		t.Fatal(err)
	}
	store, err := server.objects()
	if err != nil {
		t.Fatalf("objects(): %v", err)
	}
	if store.sealer == nil {
		t.Fatal("the store is not sealed under local-test storage")
	}
	secret := []byte("MARKER-this plaintext must never reach the disk-MARKER")
	receipt := mustPut(t, store, bytes.Repeat(secret, 50))
	segment, err := os.ReadFile(store.segmentPath(store.tailID))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(segment, secret) {
		t.Fatal("the segment holds the plaintext")
	}
	if size, err := store.stat(mustParse(t, receipt.ID)); err != nil || size != int64(len(secret)*50) {
		t.Fatalf("stat under seal: %d, %v", size, err)
	}
	if _, err := os.Stat(filepath.Join(ObjectsPath(config), objectKeyFileName)); err != nil {
		t.Fatalf("no key file beside the segments: %v", err)
	}
	server.Shutdown(context.Background())

	reopened, err := NewCore(config)
	if err != nil {
		t.Fatal(err)
	}
	again, err := reopened.objects()
	if err != nil {
		t.Fatalf("reopen under the same key: %v", err)
	}
	mustGet(t, again, receipt.ID, bytes.Repeat(secret, 50))
	reopened.Shutdown(context.Background())

	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", storageTestKey(t))
	wrongKey, err := NewCore(config)
	if err != nil {
		// The state file refuses the wrong key first; the object store is the same refusal.
		if !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("wrong key: %v", err)
		}
	} else {
		if _, err := wrongKey.objects(); err == nil {
			t.Fatal("a different wrapping key opened the sealed object store")
		}
		wrongKey.Shutdown(context.Background())
	}

	// A plaintext object store under an encrypted mode is refused, not read.
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", keyPath)
	plain := filepath.Join(t.TempDir(), "plain.objects")
	plainStore := openTestStore(t, plain, DefaultMaxObjectBytes)
	mustPut(t, plainStore, []byte("plain"))
	plainStore.close()
	storage, err := server.storageCodec()
	if err != nil || storage == nil {
		t.Fatalf("storageCodec: %v, %v", storage, err)
	}
	if _, err := openObjectStore(plain, DefaultMaxObjectBytes, storage); err == nil || !strings.Contains(err.Error(), "no object migration") {
		t.Fatalf("plaintext store under encrypted storage: %v, want a refusal", err)
	}
}

// An unsealed store is refused by an install that has turned encryption OFF for one that was sealed,
// so a key file cannot be silently ignored.
func TestSealedObjectStoreRefusesAPlaintextMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sealed.objects")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	envelope := fmt.Sprintf(`{"version":1,"id":"%s","key":{"key":"local-test/v1","ciphertext":"AA=="}}`, strings.Repeat("0", 64))
	if err := os.WriteFile(filepath.Join(dir, objectKeyFileName), []byte(envelope), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openObjectStore(dir, DefaultMaxObjectBytes, nil); err == nil || !strings.Contains(err.Error(), "requires configured storage encryption") {
		t.Fatalf("sealed store without storage: %v, want a refusal", err)
	}
}
