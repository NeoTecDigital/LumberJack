// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/ciphertext"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"io"
	"net/http"
	"strings"
)

type messageOperationInput struct {
	accountID        string
	workspaceID      string
	Content          string                            `json:"content,omitempty"`
	ClientID         string                            `json:"client_id"`
	ExpectedRevision uint64                            `json:"expected_revision,omitempty"`
	Envelope         json.RawMessage                   `json:"envelope,omitempty"`
	Context          json.RawMessage                   `json:"context,omitempty"`
	Attachments      *[]core.ConversationAttachmentRef `json:"attachments,omitempty"`
	NameEnvelope     json.RawMessage                   `json:"name_envelope,omitempty"`
	NameContext      json.RawMessage                   `json:"name_context,omitempty"`
}

func messageInput(w http.ResponseWriter, r *http.Request) (messageOperationInput, error) {
	var in messageOperationInput
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, (core.MaxAttachmentSize+16)*4/3+65536))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF {
		return in, apiErrorf(400, "Invalid message request")
	}
	if len(in.ClientID) < 1 || len(in.ClientID) > 100 || strings.TrimSpace(in.ClientID) != in.ClientID {
		return in, apiErrorf(400, "Provide a stable client identity")
	}
	return in, nil
}
func messageDigest(in messageOperationInput) string {
	raw, _ := json.Marshal(in)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
func messageStableID(conversation, user, client string) string {
	raw, _ := json.Marshal([]string{conversation, user, client})
	digest := sha256.Sum256(raw)
	return "file-" + hex.EncodeToString(digest[:])
}
func validateMessageEnvelope(raw, control json.RawMessage, account, workspace, conversation, record, kind string, revision uint64) error {
	context, err := ciphertext.ParseContext(control)
	if account == "" {
		return apiErrorf(503, "Authenticated content handoff unavailable")
	}
	if err != nil || context.AccountID != account || context.Product != "momentum" || context.WorkspaceID != workspace || context.ResourceID != conversation || context.RecordID != record || context.Kind != kind || context.Revision != revision {
		return apiErrorf(400, "Encrypted content context does not match this operation")
	}
	if _, err = ciphertext.Parse(raw, context); err != nil {
		return apiErrorf(400, "Invalid encrypted content")
	}
	return nil
}
func messageMember(c *core.Conversation, user string) (core.ConversationMember, error) {
	if c == nil {
		return core.ConversationMember{}, apiErrorf(404, "Conversation not found")
	}
	member, ok := c.Members[user]
	if !ok {
		return member, apiErrorf(404, "Conversation not found")
	}
	if member.Invited {
		return member, apiErrorf(403, "Accept the invitation first")
	}
	return member, nil
}
func messageRevision(m core.ConversationMessage) uint64 {
	if m.Revision == 0 {
		return 1
	}
	return m.Revision
}

// messagePublic strips persistence-only immutable evidence and replay receipts.
func messagePublic(m core.ConversationMessage) core.ConversationMessage {
	m.EditEvidence = nil
	m.EditReceipts = nil
	m.Revision = messageRevision(m)
	return m
}
func messageReferences(c *core.Conversation, user string, refs []core.ConversationAttachmentRef) error {
	if len(refs) > 32 {
		return apiErrorf(400, "Too many attachments")
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		file, ok := c.Attachments[ref.ID]
		if !ok || file.UploadedBy != user || ref.Version != file.Version || seen[ref.ID] {
			return apiErrorf(400, "Attachment reference is not an owned conversation upload")
		}
		seen[ref.ID] = true
	}
	return nil
}
func messageStoredScope(raw json.RawMessage, in messageOperationInput) error {
	if in.accountID == "" {
		return apiErrorf(503, "Authenticated content handoff unavailable")
	}
	context, err := ciphertext.ParseContext(raw)
	if err != nil || context.AccountID != in.accountID || context.WorkspaceID != in.workspaceID {
		return apiErrorf(404, "Encrypted content not found")
	}
	return nil
}
func messageReferenceScope(c *core.Conversation, refs []core.ConversationAttachmentRef, in messageOperationInput) error {
	for _, ref := range refs {
		if err := messageStoredScope(c.Attachments[ref.ID].Context, in); err != nil {
			return err
		}
	}
	return nil
}
