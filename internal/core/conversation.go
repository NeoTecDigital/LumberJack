// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package core

import "encoding/json"

// Conversation state is private to participants and never a forest/node projection.
type Conversation struct {
	ID        string                        `json:"id"`
	Kind      string                        `json:"kind"`
	Title     string                        `json:"title"`
	ProjectID string                        `json:"project_id,omitempty"`
	OwnerID   string                        `json:"owner_id"`
	Revision  uint64                        `json:"revision"`
	Members   map[string]ConversationMember `json:"members"`
	Messages  []ConversationMessage         `json:"messages"`
	// CreateReceipts bind a caller/client identity to its validated request digest.
	// Receipts survive ownership transfer and departure, but never grant membership.
	CreateReceipts map[string]string                 `json:"create_receipts,omitempty"`
	Attachments    map[string]ConversationAttachment `json:"attachments,omitempty"`
}
type ConversationMember struct {
	Invited        bool `json:"invited"`
	IncludeHistory bool `json:"include_history,omitempty"`
	// From is exclusive: accepted members can read sequences greater than From.
	From          uint64          `json:"from"`
	ReadThrough   uint64          `json:"read_through"`
	Muted         bool            `json:"muted"`
	Archived      bool            `json:"archived"`
	Saved         bool            `json:"saved"`
	Refused       bool            `json:"refused"`
	SavedMessages map[string]bool `json:"saved_messages,omitempty"`
}

// The initial draft encoded an invitation's history choice in an impossible
// sequence. Read that old representation once without ever writing it again.
func (m *ConversationMember) UnmarshalJSON(data []byte) error {
	type record ConversationMember
	var value record
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if value.Invited && value.From == ^uint64(0) {
		value.From = 0
		value.IncludeHistory = true
	}
	*m = ConversationMember(value)
	return nil
}

type ConversationMessage struct {
	Saved       bool                        `json:"saved"` // Projection only; private bookmarks live on the member.
	ID          string                      `json:"id"`
	Sequence    uint64                      `json:"sequence"`
	AuthorID    string                      `json:"author_id"`
	Content     string                      `json:"content"`
	At          string                      `json:"at"`
	ClientID    string                      `json:"client_id"`
	Revision    uint64                      `json:"revision,omitempty"`
	EditedAt    string                      `json:"edited_at,omitempty"`
	Envelope    json.RawMessage             `json:"envelope,omitempty"`
	Context     json.RawMessage             `json:"context,omitempty"`
	Attachments []ConversationAttachmentRef `json:"attachments,omitempty"`
	// EditEvidence persists immutable prior revisions without listing them in previews.
	EditEvidence []ConversationMessageEdit `json:"edit_evidence,omitempty"`
	EditReceipts map[string]string         `json:"edit_receipts,omitempty"`
}
type ConversationAttachmentRef struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}
type ConversationMessageEdit struct {
	Revision    uint64                      `json:"revision"`
	Content     string                      `json:"content,omitempty"`
	Envelope    json.RawMessage             `json:"envelope,omitempty"`
	Context     json.RawMessage             `json:"context,omitempty"`
	Attachments []ConversationAttachmentRef `json:"attachments,omitempty"`
	At          string                      `json:"at"`
}
type ConversationAttachment struct {
	ID           string          `json:"id"`
	Version      uint64          `json:"version"`
	UploadedBy   string          `json:"uploaded_by"`
	UploadedAt   string          `json:"uploaded_at"`
	ClientID     string          `json:"client_id"`
	Digest       string          `json:"digest"`
	Size         int             `json:"size"`
	Envelope     json.RawMessage `json:"envelope"`
	NameEnvelope json.RawMessage `json:"name_envelope"`
	Context      json.RawMessage `json:"context"`
	NameContext  json.RawMessage `json:"name_context"`
}
