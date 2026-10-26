// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import "github.com/NeoTecDigital/LumberJack/internal/core"

type messageSaveInput struct {
	ID    string `json:"id"`
	Saved *bool  `json:"saved"`
}

func messageForMember(message core.ConversationMessage, member core.ConversationMember) core.ConversationMessage {
	message = messagePublic(message)
	message.Saved = !member.Invited && message.Sequence > member.From && member.SavedMessages[message.ID]
	return message
}

func savedMessageCount(c *core.Conversation, member core.ConversationMember) int {
	if member.Invited {
		return 0
	}
	count := 0
	for _, message := range c.Messages {
		if message.Sequence > member.From && member.SavedMessages[message.ID] {
			count++
		}
	}
	return count
}

func savedMessagePatch(c *core.Conversation, member *core.ConversationMember, patch *messageSaveInput) error {
	if patch == nil {
		return nil
	}
	if patch.ID == "" || len(patch.ID) > 160 || patch.Saved == nil {
		return apiErrorf(400, "Choose a message and bookmark value")
	}
	if member.Invited {
		return apiErrorf(403, "Accept the invitation first")
	}
	for _, message := range c.Messages {
		if message.ID != patch.ID || message.Sequence <= member.From {
			continue
		}
		// Copy before editing: failed validation never mutates the stored member map.
		saved := map[string]bool{}
		for id, value := range member.SavedMessages {
			if value {
				saved[id] = true
			}
		}
		if *patch.Saved {
			saved[patch.ID] = true
		} else {
			delete(saved, patch.ID)
		}
		member.SavedMessages = saved
		return nil
	}
	return apiErrorf(404, "Message not found")
}

func (s *Server) conversationPreferences(c *core.Conversation, user string, in conversationInput) (interface{}, error) {
	member := c.Members[user]
	if in.ReadThrough != nil {
		if member.Invited {
			return nil, apiErrorf(403, "Accept the invitation before changing a message read position")
		}
		if *in.ReadThrough > uint64(len(c.Messages)) {
			return nil, apiErrorf(400, "Read position exceeds conversation")
		}
		member.ReadThrough = *in.ReadThrough
	}
	if err := savedMessagePatch(c, &member, in.MessageSave); err != nil {
		return nil, err
	}
	if in.Muted != nil {
		member.Muted = *in.Muted
	}
	if in.Archived != nil {
		member.Archived = *in.Archived
	}
	if in.Saved != nil {
		member.Saved = *in.Saved
	}
	if in.Refused != nil {
		member.Refused = *in.Refused
	}
	c.Members[user] = member
	return s.conversationView(c, user), nil
}
