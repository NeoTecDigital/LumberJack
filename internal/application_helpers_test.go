// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// Helpers for driving the application transport and the password exchange.

// applicationCall sends one request through the application transport, as the embedded and FFI
// callers do.
func applicationCall(t *testing.T, server *Server, method, target string, body interface{}) ApplicationResponse {
	t.Helper()
	var raw []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode %s %s: %v", method, target, err)
		}
		raw = encoded
	}
	return server.ApplicationCall(ApplicationRequest{Method: method, Target: target, Headers: map[string]string{"Content-Type": "application/json"}, Body: raw})
}

// decodeApplication reads a JSON answer, failing the test on a body that is not one.
func decodeApplication(t *testing.T, response ApplicationResponse) map[string]interface{} {
	t.Helper()
	var decoded map[string]interface{}
	if err := json.Unmarshal(response.Body, &decoded); err != nil {
		t.Fatalf("the answer was not JSON (status %d): %q", response.Status, string(response.Body))
	}
	return decoded
}

type loginResult struct {
	status int
	json   map[string]interface{}
}

// login posts a body to /login and answers the status and the JSON it carried.
func login(t *testing.T, server *Server, payload map[string]interface{}) loginResult {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode login body: %v", err)
	}
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleLogin(rec, req)
	result := loginResult{status: rec.Code}
	if body := rec.Body.Bytes(); len(bytes.TrimSpace(body)) > 0 && json.Valid(body) {
		_ = json.Unmarshal(body, &result.json)
	}
	return result
}
