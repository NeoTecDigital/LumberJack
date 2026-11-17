// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

const conversationParticipantLimit = 100 // Includes the owner and pending invitations.

func conversationCreateDigest(in conversationInput) string {
	names := append([]string{}, in.Usernames...)
	for i := range names {
		names[i] = strings.TrimSpace(names[i])
	}
	sort.Strings(names)
	data, _ := json.Marshal([]interface{}{in.Kind, strings.TrimSpace(in.Title), strings.Trim(in.ProjectPath, "/"), names})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func validateCreateConversation(in conversationInput) error {
	if in.Kind != "dm" && in.Kind != "group" && in.Kind != "channel" {
		return apiErrorf(400, "Choose a direct message, group or channel")
	}
	if strings.TrimSpace(in.ClientID) == "" || len(in.ClientID) > 100 || len(in.Title) > 200 || len(in.Usernames) >= conversationParticipantLimit {
		return apiErrorf(400, "Invalid conversation request; at most 100 participants including you")
	}
	if in.Kind == "dm" && len(in.Usernames) != 1 {
		return apiErrorf(400, "Choose one person for a direct message")
	}
	if in.Kind != "dm" && strings.TrimSpace(in.Title) == "" {
		return apiErrorf(400, "Name the conversation")
	}
	if in.Kind != "channel" && in.ProjectPath != "" {
		return apiErrorf(400, "Only project channels have a project association")
	}
	return nil
}

func (s *Server) findCreatedConversation(user, identity, digest string) (*core.Conversation, bool, error) {
	for _, old := range s.forest.Conversations {
		if old == nil {
			continue
		}
		stored, recorded := old.CreateReceipts[identity]
		if old.ID != identity && !recorded {
			continue
		}
		member, present := old.Members[user]
		if !present {
			return nil, false, apiErrorf(404, "Conversation not found")
		}
		if member.Invited {
			return nil, false, apiErrorf(403, "Accept the invitation before opening this conversation")
		}
		if !recorded || stored != digest {
			return nil, false, apiErrorf(409, "This conversation identity was already used with a different or legacy request")
		}
		return old, true, nil
	}
	return nil, false, nil
}

func (s *Server) resolveConversationTarget(user string, in conversationInput) (map[string]bool, string, error) {
	ids := map[string]bool{user: true}
	for _, name := range in.Usernames {
		if strings.TrimSpace(name) == "" || len(name) > 128 {
			return nil, "", apiErrorf(400, "Choose a valid participant username")
		}
		id := s.conversationAccount(name)
		if id == "" || id == user {
			return nil, "", apiErrorf(404, "Choose another available account")
		}
		ids[id] = true
	}
	if in.Kind != "channel" {
		return ids, "", nil
	}
	if strings.TrimSpace(in.ProjectPath) == "" || len(in.ProjectPath) > 4096 {
		return nil, "", apiErrorf(400, "Choose a project for the channel")
	}
	n, err := s.getNodeFromPath(in.ProjectPath)
	if err != nil || !n.CheckPermission(user, core.AdminPermission) {
		return nil, "", apiErrorf(403, "Manage the project to create a channel")
	}
	return ids, n.ID, nil
}

func sameParticipants(members map[string]core.ConversationMember, ids map[string]bool) bool {
	if len(members) != 2 {
		return false
	}
	for id := range members {
		if !ids[id] {
			return false
		}
	}
	return true
}

func (s *Server) reuseDirectConversation(user, identity, digest string, ids map[string]bool) (*core.Conversation, error) {
	for _, c := range s.forest.Conversations {
		if c == nil || c.Kind != "dm" || !sameParticipants(c.Members, ids) {
			continue
		}
		if c.Members[user].Invited {
			return nil, apiErrorf(403, "Accept the existing invitation before messaging")
		}
		if c.CreateReceipts == nil {
			c.CreateReceipts = map[string]string{}
		}
		c.CreateReceipts[identity] = digest
		return c, nil
	}
	return nil, nil
}

// All caller-controlled validation precedes map initialization or receipt writes.
// A receipt answers whether a request ran; it never grants continuing access.
func (s *Server) createConversation(user string, in conversationInput) (*core.Conversation, bool, error) {
	if err := validateCreateConversation(in); err != nil {
		return nil, false, err
	}
	identity := fmt.Sprintf("conversation-%x", sha256.Sum256([]byte(user+"\x00"+in.ClientID)))
	digest := conversationCreateDigest(in)
	if old, replayed, err := s.findCreatedConversation(user, identity, digest); err != nil || replayed {
		return old, false, err
	}
	ids, project, err := s.resolveConversationTarget(user, in)
	if err != nil {
		return nil, false, err
	}
	if in.Kind == "dm" {
		if existing, err := s.reuseDirectConversation(user, identity, digest, ids); err != nil || existing != nil {
			return existing, false, err
		}
	}
	c := &core.Conversation{ID: identity, Kind: in.Kind, Title: strings.TrimSpace(in.Title), ProjectID: project, OwnerID: user, Revision: 1, Members: map[string]core.ConversationMember{}, Messages: []core.ConversationMessage{}, CreateReceipts: map[string]string{identity: digest}}
	for id := range ids {
		c.Members[id] = core.ConversationMember{Invited: id != user}
	}
	if c.Kind == "dm" {
		c.Title = s.conversationTitle(c)
	}
	if s.forest.Conversations == nil {
		s.forest.Conversations = map[string]*core.Conversation{}
	}
	s.forest.Conversations[c.ID] = c
	return c, true, nil
}

// The native handler shares a request struct across routes, but a field for a
// different route is not an authorization hint and must not silently take effect.
func validateConversationInput(path []string, method string, in conversationInput) error {
	var reject bool
	switch {
	case len(path) == 1:
		reject = in.Content != "" || in.Action != "" || in.Username != "" || in.IncludeHistory || in.ReadThrough != nil || in.Muted != nil || in.Archived != nil
	case len(path) == 3:
		reject = in.Kind != "" || in.Title != "" || in.ProjectPath != "" || len(in.Usernames) > 0
		switch path[2] {
		case "messages":
			reject = reject || in.Action != "" || in.Username != "" || in.IncludeHistory || in.ReadThrough != nil || in.Muted != nil || in.Archived != nil
		case "membership":
			reject = reject || in.ClientID != "" || in.Content != "" || in.ReadThrough != nil || in.Muted != nil || in.Archived != nil || (in.IncludeHistory && in.Action != "invite")
		case "preferences":
			reject = reject || in.ClientID != "" || in.Content != "" || in.Action != "" || in.Username != "" || in.IncludeHistory
		}
	}
	if in.Saved != nil || in.Refused != nil || in.MessageSave != nil {
		reject = reject || len(path) != 3 || path[2] != "preferences" || method != "PATCH"
	}
	if reject {
		return apiErrorf(400, "Request fields do not match this conversation operation")
	}
	return nil
}
