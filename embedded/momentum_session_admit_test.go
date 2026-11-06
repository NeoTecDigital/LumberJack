// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package embedded

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/types"
)

// The whole personal route on the embedded handle, across a reopen: a signed admission opens the
// workspace, its command stays spent, and the person and their home are still there.
func TestMomentumDelegatedSessionServesTheWorkspaceAcrossReopens(t *testing.T) {
	isolatedApplicationSecurity(t)
	key := ed25519.NewKeyFromSeed(append(make([]byte, 31), 3))
	config := SessionAdmissionConfig{KeyID: "personal", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		Issuer: "activity-personal:install", Audience: "momentum-personal:install"}
	cfg := Config{Process: types.ProcessInfo{Name: "momentum", DatabasePath: filepath.Join(t.TempDir(), "store")}}
	password, secret := applicationCredential(), applicationCredential()
	open := func() *Handle {
		t.Helper()
		handle, err := Open(cfg, "corresponder-service")
		if err != nil {
			t.Fatal(err)
		}
		if err = handle.ConfigureApplication("operator", password, secret); err != nil {
			t.Fatal(err)
		}
		if err = handle.ConfigureSessionAdmission(config); err != nil {
			t.Fatal(err)
		}
		return handle
	}
	handle := open()
	defer func() { handle.Close() }()
	call := func(method, target, token string, body interface{}) ApplicationResponse {
		t.Helper()
		encoded, _ := json.Marshal(body)
		answer, err := handle.ApplicationCall(ApplicationRequest{Method: method, Target: target, Body: encoded,
			Headers: map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}})
		if err != nil {
			t.Fatal(err)
		}
		return answer
	}
	principal := "bootstrap-owner-embedded"
	admission := signedSessionAdmission(t, key, config, principal, "command-one")
	admitted := call("POST", "/session/admit", "", map[string]string{"admission": admission})
	if admitted.Status != 200 {
		t.Fatalf("admission: %d %s", admitted.Status, admitted.Body)
	}
	var session struct {
		Token    string `json:"token"`
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(admitted.Body, &session); err != nil || session.ID != principal || session.Username != "embedded@example.test" {
		t.Fatalf("admission answer: %v %s", err, admitted.Body)
	}
	var view struct {
		Nodes []struct {
			Path string `json:"path"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(call("GET", "/workspace", session.Token, nil).Body, &view); err != nil || len(view.Nodes) == 0 {
		t.Fatalf("workspace: %v", err)
	}
	home := map[string]string{"command": "initialize", "path": view.Nodes[0].Path, "client_id": "home"}
	if got := call("POST", "/workspace/commands", session.Token, home); got.Status != 200 {
		t.Fatalf("initialize: %d %s", got.Status, got.Body)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	handle = open()
	if got := call("GET", "/principal", session.Token, nil); got.Status != 200 {
		t.Fatalf("the session did not survive the reopen: %d %s", got.Status, got.Body)
	}
	if got := call("POST", "/session/admit", "", map[string]string{"admission": admission}); got.Status != 401 {
		t.Fatalf("a reopen forgot the spent command: %d %s", got.Status, got.Body)
	}
	again := call("POST", "/session/admit", "", map[string]string{"admission": signedSessionAdmission(t, key, config, principal, "command-two")})
	if again.Status != 200 {
		t.Fatalf("a fresh admission after the reopen: %d %s", again.Status, again.Body)
	}
	if got := call("DELETE", "/session", session.Token, nil); got.Status != 200 {
		t.Fatalf("sign-out: %d %s", got.Status, got.Body)
	}
	if got := call("GET", "/workspace", session.Token, nil); got.Status != 401 {
		t.Fatalf("a signed-out session still reads: %d", got.Status)
	}
}

func signedSessionAdmission(t *testing.T, key ed25519.PrivateKey, config SessionAdmissionConfig, principal, command string) string {
	t.Helper()
	profile := `{"email":"embedded@example.test","username":"embedded@example.test"}`
	digest := sha256.Sum256([]byte(profile))
	claims := map[string]interface{}{"version": 1, "issuer": config.Issuer, "audience": config.Audience, "principalId": principal, "sessionId": "source-session",
		"scope": map[string]string{"accountId": "personal-account", "product": "momentum"}, "grantRevision": "sha256:grant", "resourceRevision": "personal-session/0.1",
		"resourceId": principal, "operation": "personal.session.admit", "commandId": command, "bodySha256": hex.EncodeToString(digest[:]),
		"expiresAt": time.Now().Unix() + 45, "barrierVersion": 1}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]string{"keyId": config.KeyID, "payload": base64.RawURLEncoding.EncodeToString(raw),
		"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))})
	if err != nil {
		t.Fatal(err)
	}
	return `{"envelope":` + string(envelope) + `,"profile":` + profile + `}`
}
