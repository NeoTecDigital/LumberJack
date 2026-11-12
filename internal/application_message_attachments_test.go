// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"encoding/base64"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/internal/ciphertext"
	"testing"
)

func uploadFixture() messageOperationInput {
	envelope := ciphertext.Envelope{Version: 1, Algorithm: "AES-256-GCM", KeyID: "epoch",
		IV: base64.RawURLEncoding.EncodeToString(make([]byte, 12)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 20))}
	context := ciphertext.Context{Version: 1, AccountID: "activation-account", Product: "momentum", ResourceID: "conversation", RecordID: "upload", Revision: 1, KeyID: "epoch", Kind: "file"}
	raw, _ := json.Marshal(envelope)
	control, _ := json.Marshal(context)
	context.Kind = "filename"
	nameControl, _ := json.Marshal(context)
	return messageOperationInput{ClientID: "upload", Envelope: raw, Context: control, NameEnvelope: raw, NameContext: nameControl, accountID: "activation-account"}
}
func TestEncryptedUploadPersistsPendingAndReplay(t *testing.T) {
	_, c, member := messageFixture()
	in := uploadFixture()
	first, err := messageUpload(c, "native-user", in)
	if err != nil {
		t.Fatal(err)
	}
	id := first.(map[string]interface{})["id"].(string)
	if c.Attachments[id].UploadedBy != "native-user" {
		t.Fatal("caller identity substituted")
	}
	if !messageFileVisible(c, member, "native-user", id) {
		t.Fatal("pending upload not recoverable")
	}
	if messageFileVisible(c, member, "bob", id) {
		t.Fatal("pending upload leaked")
	}
	if _, err = messageUpload(c, "native-user", in); err != nil || len(c.Attachments) != 1 {
		t.Fatal("replay duplicated upload")
	}
	refs := []core.ConversationAttachmentRef{{ID: id, Version: 1}}
	c.Messages = []core.ConversationMessage{{Sequence: 1, Attachments: refs}}
	if !messageFileVisible(c, member, "bob", id) {
		t.Fatal("association did not enable authorized read")
	}
}
func TestEncryptedUploadRequiresTrustedAccountScope(t *testing.T) {
	_, c, _ := messageFixture()
	in := uploadFixture()
	in.accountID = ""
	if _, err := messageUpload(c, "native-user", in); err == nil {
		t.Fatal("missing admission scope accepted")
	}
	in.accountID = "native-user"
	if _, err := messageUpload(c, "native-user", in); err == nil {
		t.Fatal("principal substituted for Activation account")
	}
	in = uploadFixture()
	in.workspaceID = "foreign"
	if _, err := messageUpload(c, "native-user", in); err == nil {
		t.Fatal("workspace scope substitution accepted")
	}
	if len(c.Attachments) != 0 {
		t.Fatal("rejected upload mutated conversation")
	}
}
