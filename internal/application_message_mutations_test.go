// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"testing"
)

func messageFixture() (*Server, *core.Conversation, core.ConversationMember) {
	member := core.ConversationMember{}
	c := &core.Conversation{ID: "conversation", Members: map[string]core.ConversationMember{"alice": member, "bob": member}, Revision: 1}
	return &Server{}, c, member
}
func TestMessageAuthorRevisionAndImmutableHistory(t *testing.T) {
	s, c, member := messageFixture()
	value, err := s.messageSend(c, member, "alice", messageOperationInput{Content: "original", ClientID: "send"})
	if err != nil {
		t.Fatal(err)
	}
	message := value.(core.ConversationMessage)
	edit := messageOperationInput{Content: "edited", ClientID: "edit", ExpectedRevision: 1}
	if _, err = s.messageEdit(c, member, "bob", message.ID, edit); err == nil {
		t.Fatal("non-author edit accepted")
	}
	if _, err = s.messageEdit(c, member, "alice", message.ID, edit); err != nil {
		t.Fatal(err)
	}
	if c.Messages[0].ID != message.ID || c.Messages[0].Sequence != message.Sequence {
		t.Fatal("edit changed message identity")
	}
	if len(c.Messages[0].EditEvidence) != 1 || c.Messages[0].EditEvidence[0].Content != "original" {
		t.Fatal("original evidence lost")
	}
	if _, err = s.messageEdit(c, member, "alice", message.ID, edit); err != nil {
		t.Fatal("replay refused", err)
	}
	if len(c.Messages[0].EditEvidence) != 1 {
		t.Fatal("replay duplicated history")
	}
	edit.ClientID = "stale"
	if _, err = s.messageEdit(c, member, "alice", message.ID, edit); err == nil {
		t.Fatal("stale edit accepted")
	}
	history, err := messageHistory(c, member, message.ID)
	if err != nil || len(history.(map[string]interface{})["items"].([]core.ConversationMessageEdit)) != 2 {
		t.Fatal("history incomplete")
	}
}
func TestMessageExclusiveBoundaryAndRemovedMember(t *testing.T) {
	s, c, member := messageFixture()
	value, _ := s.messageSend(c, member, "alice", messageOperationInput{Content: "old", ClientID: "send"})
	message := value.(core.ConversationMessage)
	member.From = message.Sequence
	if _, err := messageHistory(c, member, message.ID); err == nil {
		t.Fatal("exclusive history boundary bypassed")
	}
	if _, err := s.messageEdit(c, member, "alice", message.ID, messageOperationInput{Content: "edit", ClientID: "edit", ExpectedRevision: 1}); err == nil {
		t.Fatal("exclusive edit boundary bypassed")
	}
	c.Members["bob"] = core.ConversationMember{Invited: true}
	if _, err := messageMember(c, "bob"); err == nil {
		t.Fatal("invitation unlocked content")
	}
	delete(c.Members, "bob")
	if _, err := messageMember(c, "bob"); err == nil {
		t.Fatal("revoked membership unlocked content")
	}
}
func TestMessageAttachmentsCannotCrossConversationOrOwner(t *testing.T) {
	_, c, member := messageFixture()
	c.Attachments = map[string]core.ConversationAttachment{"file": {ID: "file", Version: 1, UploadedBy: "alice"}}
	refs := []core.ConversationAttachmentRef{{ID: "file", Version: 1}}
	if messageReferences(c, "bob", refs) == nil {
		t.Fatal("another uploader's pending file claimed")
	}
	if messageFileVisible(c, member, "bob", "file") {
		t.Fatal("pending upload visible to another member")
	}
	c.Messages = []core.ConversationMessage{{ID: "m", Sequence: 1, Attachments: refs}}
	if !messageFileVisible(c, member, "bob", "file") {
		t.Fatal("linked file missing")
	}
	member.From = 1
	if messageFileVisible(c, member, "bob", "file") {
		t.Fatal("file bypassed history boundary")
	}
	if messageReferences(c, "alice", []core.ConversationAttachmentRef{{ID: "other", Version: 1}}) == nil {
		t.Fatal("foreign reference accepted")
	}
}
