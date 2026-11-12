// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"encoding/base64"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/internal/ciphertext"
	"time"
)

func (s *Server) messageAttachment(c *core.Conversation, member core.ConversationMember, user string, pieces []string, method string, in messageOperationInput) (interface{}, error) {
	if len(pieces) == 3 && method == "POST" {
		return messageUpload(c, user, in)
	}
	if len(pieces) != 4 || method != "GET" {
		return nil, apiErrorf(404, "Attachment operation not found")
	}
	file, ok := c.Attachments[pieces[3]]
	if !ok || !messageFileVisible(c, member, user, file.ID) {
		return nil, apiErrorf(404, "Attachment not found")
	}
	if err := messageStoredScope(file.Context, in); err != nil {
		return nil, err
	}
	return file, nil
}
func messageFileVisible(c *core.Conversation, member core.ConversationMember, user, id string) bool {
	// Unlinked uploads remain recoverable by their uploader, not every member.
	file := c.Attachments[id]
	if file.UploadedBy == user {
		return true
	}
	for _, m := range c.Messages {
		if m.Sequence <= member.From {
			continue
		}
		if referencesFile(m.Attachments, id) {
			return true
		}
		for _, edit := range m.EditEvidence {
			if referencesFile(edit.Attachments, id) {
				return true
			}
		}
	}
	return false
}
func referencesFile(refs []core.ConversationAttachmentRef, id string) bool {
	for _, ref := range refs {
		if ref.ID == id {
			return true
		}
	}
	return false
}
func messageUpload(c *core.Conversation, user string, in messageOperationInput) (interface{}, error) {
	if in.Content != "" || in.Attachments != nil || in.ExpectedRevision != 0 {
		return nil, apiErrorf(400, "Provide only encrypted file content and filename")
	}
	if err := validateMessageEnvelope(in.Envelope, in.Context, in.accountID, in.workspaceID, c.ID, in.ClientID, "file", 1); err != nil {
		return nil, err
	}
	if err := validateMessageEnvelope(in.NameEnvelope, in.NameContext, in.accountID, in.workspaceID, c.ID, in.ClientID, "filename", 1); err != nil {
		return nil, err
	}
	var envelope, name ciphertext.Envelope
	json.Unmarshal(in.Envelope, &envelope)
	json.Unmarshal(in.NameEnvelope, &name)
	bytes, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || int64(len(bytes)) > core.MaxAttachmentSize+16 {
		return nil, tooLarge()
	}
	nameBytes, _ := base64.RawURLEncoding.DecodeString(name.Ciphertext)
	if len(nameBytes) > 4096+16 {
		return nil, apiErrorf(400, "Encrypted filename too large")
	}
	fileID := messageStableID(c.ID, user, in.ClientID)
	digest := messageDigest(in)
	if prior, ok := c.Attachments[fileID]; ok {
		if prior.Digest != digest {
			return nil, apiErrorf(409, "This upload identity was already used")
		}
		return messageFileReceipt(prior), nil
	}
	file := core.ConversationAttachment{ID: fileID, Version: 1, UploadedBy: user, UploadedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ClientID: in.ClientID, Digest: digest, Size: len(bytes) - 16, Envelope: in.Envelope, NameEnvelope: in.NameEnvelope, Context: in.Context, NameContext: in.NameContext}
	if c.Attachments == nil {
		c.Attachments = map[string]core.ConversationAttachment{}
	}
	c.Attachments[fileID] = file
	c.Revision++
	return messageFileReceipt(file), nil
}
func messageFileReceipt(file core.ConversationAttachment) map[string]interface{} {
	return map[string]interface{}{"id": file.ID, "version": file.Version, "size": file.Size, "uploaded_by": file.UploadedBy,
		"uploaded_at": file.UploadedAt, "mode": "encrypted", "pending_association": true}
}
