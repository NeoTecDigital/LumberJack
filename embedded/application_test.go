package embedded

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func applicationCredential() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func TestApplicationNeverBorrowsTheBootstrapPrincipal(t *testing.T) {
	cfg := embeddedConfig(t)
	handle, err := Open(cfg, "untrusted-before-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	password, key := applicationCredential(), applicationCredential()
	if err := handle.ConfigureApplication("operator", password, key); err != nil {
		t.Fatal(err)
	}
	call := func(method, target, token string, body interface{}) ApplicationResponse {
		t.Helper()
		encoded, _ := json.Marshal(body)
		result, err := handle.ApplicationCall(ApplicationRequest{Method: method, Target: target, Headers: map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}, Body: encoded})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if got := call("GET", "/workspace", "", nil); got.Status != 401 {
		t.Fatalf("anonymous: %d", got.Status)
	}
	login := call("POST", "/login", "", map[string]string{"username": "operator", "password": password})
	if login.Status != 200 {
		t.Fatalf("login: %s", login.Body)
	}
	var tokens map[string]string
	_ = json.Unmarshal(login.Body, &tokens)
	token := tokens["session_token"]
	if got := call("GET", "/workspace", token, nil); got.Status != 200 {
		t.Fatalf("workspace: %s", got.Body)
	}
	if got := call("POST", "/users/create", token, map[string]string{"username": "guest", "password": applicationCredential(), "email": "guest@example.test"}); got.Status != 200 {
		t.Fatalf("create: %s", got.Body)
	}
	// An already-open handle cannot retain the system identity when application
	// accounts arrive, and a newly opened stranger cannot inherit it either.
	for _, principal := range []string{"untrusted-before-bootstrap", "untrusted-after-bootstrap"} {
		candidate := handle
		if principal == "untrusted-after-bootstrap" {
			candidate, err = Open(cfg, principal)
			if err != nil {
				t.Fatal(err)
			}
			defer candidate.Close()
		}
		if _, err := candidate.StatusOf("forest"); err == nil {
			t.Fatalf("%s inherited bootstrap authority", principal)
		}
	}
}
