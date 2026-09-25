// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// Application fixtures use the production MFA policy and an isolated encrypted
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
	t.Setenv("MOMENTUM_REQUIRE_MFA", "true")
}

func applicationMFALogin(t *testing.T, h *Handle, username, password string) string {
	t.Helper()
	call := func(target string, body map[string]string) map[string]interface{} {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		answer, err := h.ApplicationCall(ApplicationRequest{Method: "POST", Target: target, Headers: map[string]string{"Content-Type": "application/json"}, Body: encoded})
		if err != nil || answer.Status != 200 {
			t.Fatalf("%s: error %v, status %d", target, err, answer.Status)
		}
		var result map[string]interface{}
		if err := json.Unmarshal(answer.Body, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	challenge := call("/login", map[string]string{"username": username, "password": password})
	if challenge["mfa_required"] != true || challenge["method"] != "totp_enroll" || challenge["session_token"] != nil {
		t.Fatal("fresh account must complete enrollment before receiving a session")
	}
	code, err := totp.GenerateCode(challenge["secret"].(string), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verified := call("/mfa/verify", map[string]string{"challenge": challenge["challenge"].(string), "code": code})
	token, ok := verified["session_token"].(string)
	if !ok || token == "" {
		t.Fatal("verified enrollment did not return a session")
	}
	return token
}
