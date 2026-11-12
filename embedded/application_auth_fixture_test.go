// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Application fixtures use an isolated encrypted
// store. The same key remains available across each fixture's restart sequence.
func isolatedApplicationSecurity(t *testing.T) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wrapping.key")
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CORRESPONDER_STORAGE_MODE", "local-test")
	t.Setenv("CORRESPONDER_STORAGE_LOCAL_KEY_FILE", path)
	t.Setenv("CORRESPONDER_STORAGE_MIGRATE_LEGACY", "0")
	t.Setenv("CORRESPONDER_STORAGE_REWRAP_KEYS", "0")
	t.Setenv("CORRESPONDER_ADMIN_RECONCILE", "0")
}

// applicationLogin signs in through the application transport's /login and answers the session
// token. A generic build registers no second factor, so a password is the whole exchange.
func applicationLogin(t *testing.T, h *Handle, username, password string) string {
	t.Helper()
	encoded, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	answer, err := h.ApplicationCall(ApplicationRequest{Method: "POST", Target: "/login", Headers: map[string]string{"Content-Type": "application/json"}, Body: encoded})
	if err != nil || answer.Status != 200 {
		t.Fatalf("/login: error %v, status %d", err, answer.Status)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(answer.Body, &result); err != nil {
		t.Fatal(err)
	}
	token, ok := result["session_token"].(string)
	if !ok || token == "" {
		t.Fatal("a password login did not return a session")
	}
	return token
}
