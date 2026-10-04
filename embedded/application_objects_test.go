// Written by Richard Christopher, Copyright 2026 Richard Christopher
package embedded

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
)

// The object routes through the in-process `call` path, as the C ABI reaches them: the request and
// the response are JSON envelopes, and a binary body travels as the standard base64 Go gives a
// []byte field. The fixture runs under local-test storage, so this is also the sealed path end to
// end. The envelope is marshalled and unmarshalled here on purpose — the bytes a C caller would
// hand ic_lj_application_call are what reach ApplicationCall, not a Go value.
func TestApplicationCallCarriesObjectsAsBase64(t *testing.T) {
	isolatedApplicationSecurity(t)
	handle, err := Open(embeddedConfig(t), "operator-handle")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	password, key := applicationCredential(), applicationCredential()
	if err := handle.ConfigureApplication("operator", password, key); err != nil {
		t.Fatal(err)
	}
	token := applicationMFALogin(t, handle, "operator", password)

	body := make([]byte, 300000)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	body[0], body[1], body[2] = 0x00, 0xff, '"' // bytes JSON could not carry raw

	call := func(method, target string, payload []byte) ApplicationResponse {
		t.Helper()
		encoded, err := json.Marshal(ApplicationRequest{Method: method, Target: target, Headers: map[string]string{"Authorization": "Bearer " + token}, Body: payload})
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) > 0 && !bytes.Contains(encoded, []byte(base64.StdEncoding.EncodeToString(payload))) {
			t.Fatal("the envelope does not carry the body as standard base64")
		}
		var request ApplicationRequest
		if err := json.Unmarshal(encoded, &request); err != nil {
			t.Fatal(err)
		}
		answer, err := handle.ApplicationCall(request)
		if err != nil {
			t.Fatal(err)
		}
		// The same hop on the way out: what the C caller receives is the marshalled envelope.
		wire, err := json.Marshal(answer)
		if err != nil {
			t.Fatal(err)
		}
		var decoded ApplicationResponse
		if err := json.Unmarshal(wire, &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}

	put := call("POST", "/objects", body)
	if put.Status != 200 {
		t.Fatalf("POST /objects: %d %s", put.Status, put.Body)
	}
	var receipt struct {
		ID      string `json:"id"`
		Size    int64  `json:"size"`
		Existed bool   `json:"existed"`
	}
	if err := json.Unmarshal(put.Body, &receipt); err != nil || receipt.Size != int64(len(body)) || receipt.Existed {
		t.Fatalf("receipt %s: %v", put.Body, err)
	}
	if again := call("POST", "/objects", body); !bytes.Contains(again.Body, []byte(`"existed":true`)) {
		t.Fatalf("second put: %s", again.Body)
	}

	got := call("GET", "/objects/"+receipt.ID, nil)
	if got.Status != 200 || !bytes.Equal(got.Body, body) {
		t.Fatalf("GET /objects/{id}: %d, %d bytes back, want the %d that went up", got.Status, len(got.Body), len(body))
	}
	head := call("HEAD", "/objects/"+receipt.ID, nil)
	if head.Status != 200 || len(head.Body) != 0 || head.Headers["Content-Length"] != strconv.Itoa(len(body)) {
		t.Fatalf("HEAD /objects/{id}: %d, %d body bytes, headers %v", head.Status, len(head.Body), head.Headers)
	}
	if anonymous, _ := handle.ApplicationCall(ApplicationRequest{Method: "GET", Target: "/objects/" + receipt.ID}); anonymous.Status != 401 {
		t.Fatalf("anonymous GET through call: %d, want 401", anonymous.Status)
	}
}
