// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/core"
	"strings"
	"time"
)

func messageBody(in messageOperationInput, user, conversation string, revision uint64) error {
	if len(in.Envelope) > 0 {
		if len(in.Envelope) > (65536+16)*4/3+1024 {
			return apiErrorf(400, "Encrypted message too large")
		}
		if in.Content != "" {
			return apiErrorf(400, "Do not mix plaintext and encrypted content")
		}
		if err := validateMessageEnvelope(in.Envelope, in.Context, in.accountID, in.workspaceID, conversation, in.ClientID, "body", revision); err != nil {
			return err
		}
		var envelope struct {
			Ciphertext string `json:"ciphertext"`
		}
		json.Unmarshal(in.Envelope, &envelope)
		bytes, _ := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
		if len(bytes) > 65536+16 {
			return apiErrorf(400, "Encrypted message too large")
		}
		return nil
	}
	if len(in.Context) > 0 || strings.TrimSpace(in.Content) == "" || len(in.Content) > 65536 {
		return apiErrorf(400, "Write a message of up to 65536 bytes")
	}
	return nil
}
func (s *Server) messageSend(c *core.Conversation, member core.ConversationMember, user string, in messageOperationInput) (interface{}, error) {
	if in.ExpectedRevision != 0 || len(in.NameEnvelope) > 0 || len(in.NameContext) > 0 {
		return nil, apiErrorf(400, "Invalid send fields")
	}
	if err := messageBody(in, user, c.ID, 1); err != nil {
		return nil, err
	}
	refs := []core.ConversationAttachmentRef{}
	if in.Attachments != nil {
		refs = *in.Attachments
	}
	if err := messageReferences(c, user, refs); err != nil {
		return nil, err
	}
	if err := messageReferenceScope(c, refs, in); err != nil {
		return nil, err
	}
	for _, m := range c.Messages {
		if m.AuthorID != user || m.ClientID != in.ClientID {
			continue
		}
		if m.Sequence <= member.From || !messageSendMatches(m, in) {
			return nil, apiErrorf(409, "This message identity was already used")
		}
		return messageForMember(m, member), nil
	}
	seq := uint64(len(c.Messages) + 1)
	m := core.ConversationMessage{ID: fmt.Sprintf("%s:%d", c.ID, seq), Sequence: seq, AuthorID: user,
		Content: in.Content, At: time.Now().UTC().Format(time.RFC3339Nano), ClientID: in.ClientID, Revision: 1,
		Envelope: in.Envelope, Context: in.Context, Attachments: append([]core.ConversationAttachmentRef{}, refs...)}
	c.Messages = append(c.Messages, m)
	c.Revision++
	member.Archived = false
	c.Members[user] = member
	return messageForMember(m, member), nil
}
func messageSendMatches(m core.ConversationMessage, in messageOperationInput) bool {
	initial := messageEvidence(m)
	if len(m.EditEvidence) > 0 {
		initial = m.EditEvidence[0]
	}
	refs := []core.ConversationAttachmentRef{}
	if in.Attachments != nil {
		refs = *in.Attachments
	}
	originalRefs := append([]core.ConversationAttachmentRef{}, initial.Attachments...)
	original := messageOperationInput{Content: initial.Content, ClientID: m.ClientID, Envelope: initial.Envelope, Context: initial.Context, Attachments: &originalRefs}
	incoming := in
	incoming.Attachments = &refs
	return messageDigest(original) == messageDigest(incoming)
}
func messageEvidence(m core.ConversationMessage) core.ConversationMessageEdit {
	at := m.EditedAt
	if at == "" {
		at = m.At
	}
	return core.ConversationMessageEdit{Revision: messageRevision(m), Content: m.Content, Envelope: append([]byte{}, m.Envelope...),
		Context: append([]byte{}, m.Context...), Attachments: append([]core.ConversationAttachmentRef{}, m.Attachments...), At: at}
}
func messageFind(c *core.Conversation, member core.ConversationMember, user, id string) (int, error) {
	for i, m := range c.Messages {
		if m.ID != id || m.Sequence <= member.From {
			continue
		}
		if m.AuthorID != user {
			return 0, apiErrorf(403, "Only the author may edit a message")
		}
		return i, nil
	}
	return 0, apiErrorf(404, "Message not found")
}
func (s *Server) messageEdit(c *core.Conversation, member core.ConversationMember, user, id string, in messageOperationInput) (interface{}, error) {
	index, err := messageFind(c, member, user, id)
	if err != nil {
		return nil, err
	}
	m := c.Messages[index]
	digest := messageDigest(in)
	if receipt, ok := m.EditReceipts[in.ClientID]; ok {
		if receipt != digest {
			return nil, apiErrorf(409, "This edit identity was already used")
		}
		return messageForMember(m, member), nil
	}
	if in.ExpectedRevision == 0 || in.ExpectedRevision >= 9007199254740991 || messageRevision(m) != in.ExpectedRevision {
		return nil, apiErrorf(409, "Message revision changed")
	}
	if len(in.NameEnvelope) > 0 || len(in.NameContext) > 0 {
		return nil, apiErrorf(400, "Invalid edit fields")
	}
	if len(m.Envelope) > 0 && len(in.Envelope) == 0 {
		return nil, apiErrorf(400, "Encrypted messages require encrypted edits")
	}
	if err = messageBody(in, user, c.ID, in.ExpectedRevision+1); err != nil {
		return nil, err
	}
	refs := m.Attachments
	if in.Attachments != nil {
		refs = *in.Attachments
	}
	if err = messageReferences(c, user, refs); err != nil {
		return nil, err
	}
	if err = messageReferenceScope(c, refs, in); err != nil {
		return nil, err
	}
	m = messageApplyEdit(m, in, refs, digest)
	c.Messages[index] = m
	c.Revision++
	return messageForMember(m, member), nil
}
func messageApplyEdit(m core.ConversationMessage, in messageOperationInput, refs []core.ConversationAttachmentRef, digest string) core.ConversationMessage {
	m.EditEvidence = append(m.EditEvidence, messageEvidence(m))
	m.Content = in.Content
	m.Envelope = in.Envelope
	m.Context = in.Context
	m.Attachments = append([]core.ConversationAttachmentRef{}, refs...)
	m.Revision = in.ExpectedRevision + 1
	m.EditedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if m.EditReceipts == nil {
		m.EditReceipts = map[string]string{}
	}
	m.EditReceipts[in.ClientID] = digest
	return m
}
