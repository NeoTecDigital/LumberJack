// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"strings"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

func (s *Server) changeConversationMembership(c *core.Conversation, user string, in conversationInput) (interface{}, error) {
	member := c.Members[user]
	switch in.Action {
	case "accept":
		if in.Username != "" {
			return nil, apiErrorf(400, "Accept your own invitation")
		}
		if member.Invited {
			member.Invited = false
			// A DM's initial messages were addressed to its sole invited recipient.
			// Group/channel history is hidden unless its owner explicitly included it.
			if c.Kind != "dm" && !member.IncludeHistory {
				member.From = uint64(len(c.Messages))
			} else {
				member.From = 0
			}
			member.IncludeHistory = false
			member.ReadThrough = member.From
			c.Members[user] = member
			c.Revision++
		}
	case "leave":
		if in.Username != "" {
			return nil, apiErrorf(400, "Leave your own membership")
		}
		if c.OwnerID == user {
			return nil, apiErrorf(409, "Transfer ownership before leaving")
		}
		delete(c.Members, user)
		c.Revision++
		return map[string]interface{}{"left": true}, nil
	case "invite", "remove", "transfer":
		if c.OwnerID != user || member.Invited {
			return nil, apiErrorf(403, "Only the conversation owner can manage membership")
		}
		if c.Kind == "dm" && in.Action == "invite" {
			return nil, apiErrorf(409, "Create a group to add participants")
		}
		if strings.TrimSpace(in.Username) == "" || len(in.Username) > 128 {
			return nil, apiErrorf(400, "Choose a participant")
		}
		id := s.conversationAccount(in.Username)
		if id == "" {
			return nil, apiErrorf(404, "Account unavailable")
		}
		current, exists := c.Members[id]
		switch in.Action {
		case "invite":
			if exists {
				return s.conversationView(c, user), nil
			}
			if len(c.Members) >= conversationParticipantLimit {
				return nil, apiErrorf(409, "The conversation has reached its 100-participant limit")
			}
			c.Members[id] = core.ConversationMember{Invited: true, From: uint64(len(c.Messages)), IncludeHistory: in.IncludeHistory}
		case "remove":
			if id == c.OwnerID {
				return nil, apiErrorf(409, "Transfer ownership before removing the owner")
			}
			if !exists {
				return nil, apiErrorf(404, "Participant unavailable")
			}
			delete(c.Members, id)
		case "transfer":
			if !exists || current.Invited {
				return nil, apiErrorf(400, "Choose an active participant")
			}
			if c.OwnerID == id {
				return s.conversationView(c, user), nil
			}
			c.OwnerID = id
		}
		c.Revision++
	default:
		return nil, apiErrorf(400, "Unknown membership action")
	}
	return s.conversationView(c, user), nil
}
