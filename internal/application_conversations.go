// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"fmt"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type conversationInput struct {
	Kind           string            `json:"kind,omitempty"`
	Title          string            `json:"title,omitempty"`
	ProjectPath    string            `json:"project_path,omitempty"`
	Usernames      []string          `json:"usernames,omitempty"`
	ClientID       string            `json:"client_id,omitempty"`
	Content        string            `json:"content,omitempty"`
	Action         string            `json:"action,omitempty"`
	Username       string            `json:"username,omitempty"`
	IncludeHistory bool              `json:"include_history,omitempty"`
	ReadThrough    *uint64           `json:"read_through,omitempty"`
	Muted          *bool             `json:"muted,omitempty"`
	Archived       *bool             `json:"archived,omitempty"`
	Saved          *bool             `json:"saved,omitempty"`
	Refused        *bool             `json:"refused,omitempty"`
	MessageSave    *messageSaveInput `json:"message_save,omitempty"`
}

func (s *Server) conversationUsername(id string) string {
	p, err := s.forest.GetUserProfile(id)
	if err != nil {
		return "Former member"
	}
	return p.Username
}
func (s *Server) conversationAccount(username string) string {
	for _, u := range s.forest.Users {
		if u.Username == strings.TrimSpace(username) && u.ID != SystemUserID {
			return u.ID
		}
	}
	return ""
}

// conversationTitle reads a direct message's title from its people as they are named now: an account
// can be renamed by its next admission, and the name it was created under must not stay on screen.
func (s *Server) conversationTitle(c *core.Conversation) string {
	if c.Kind != "dm" {
		return c.Title
	}
	names := []string{}
	for id := range c.Members {
		names = append(names, s.conversationUsername(id))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
func conversationPreview(c *core.Conversation, user string, own core.ConversationMember) (interface{}, int) {
	if own.Invited {
		return nil, 0
	}
	unread := 0
	var preview interface{}
	for _, m := range c.Messages {
		if m.Sequence <= own.From {
			continue
		}
		preview = messageForMember(m, own)
		if m.Sequence > own.ReadThrough && m.AuthorID != user {
			unread++
		}
	}
	return preview, unread
}

func (s *Server) conversationView(c *core.Conversation, user string) map[string]interface{} {
	own := c.Members[user]
	preview, unread := conversationPreview(c, user, own)
	people := []map[string]interface{}{}
	for id, m := range c.Members {
		people = append(people, map[string]interface{}{"id": id, "username": s.conversationUsername(id), "invited": m.Invited, "owner": id == c.OwnerID})
	}
	sort.Slice(people, func(i, j int) bool { return people[i]["id"].(string) < people[j]["id"].(string) })
	// Project association conveys no entitlement to the project or its title.
	return map[string]interface{}{"id": c.ID, "kind": c.Kind, "title": s.conversationTitle(c), "project_id": c.ProjectID, "revision": c.Revision, "members": people, "invited": own.Invited, "muted": own.Muted, "archived": own.Archived, "saved": own.Saved, "refused": own.Refused, "saved_message_count": savedMessageCount(c, own), "unread": unread, "last_message": preview, "read_through": own.ReadThrough, "history_from": own.From}
}

func decodeConversationBody(w http.ResponseWriter, r *http.Request, pieces []string) (conversationInput, bool) {
	var in conversationInput
	if r.Method == "GET" {
		return in, true
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil {
		http.Error(w, "Invalid conversation request", 400)
		return in, false
	}
	var trailing interface{}
	if decoder.Decode(&trailing) != io.EOF {
		http.Error(w, "Provide one complete conversation request", 400)
		return in, false
	}
	if err := validateConversationInput(pieces, r.Method, in); err != nil {
		writeAPIError(w, err)
		return in, false
	}
	return in, true
}

func (s *Server) listConversations(user string) map[string]interface{} {
	items := []map[string]interface{}{}
	for _, c := range s.forest.Conversations {
		if _, ok := c.Members[user]; ok {
			items = append(items, s.conversationView(c, user))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["id"].(string) < items[j]["id"].(string) })
	return map[string]interface{}{"items": items}
}

func conversationMessagesPage(c *core.Conversation, member core.ConversationMember, rawBefore string) (interface{}, error) {
	before := uint64(len(c.Messages) + 1)
	if rawBefore != "" {
		n, err := strconv.ParseUint(rawBefore, 10, 64)
		if err != nil || n == 0 {
			return nil, apiErrorf(400, "Invalid message cursor")
		}
		before = n
	}
	items := []core.ConversationMessage{}
	for i := len(c.Messages) - 1; i >= 0 && len(items) < 50; i-- {
		m := c.Messages[i]
		if m.Sequence < before && m.Sequence > member.From {
			items = append(items, messageForMember(m, member))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Sequence < items[j].Sequence })
	var next interface{}
	if len(items) == 50 && items[0].Sequence > member.From+1 {
		next = items[0].Sequence
	}
	return map[string]interface{}{"items": items, "next_before": next}, nil
}

func appendLegacyMessage(c *core.Conversation, member core.ConversationMember, user string, in conversationInput) (interface{}, mutationEvent, error) {
	if strings.TrimSpace(in.Content) == "" || len(in.Content) > 65536 || len(in.ClientID) < 1 || len(in.ClientID) > 100 {
		return nil, mutationEvent{}, apiErrorf(400, "Write a message of up to 65536 bytes")
	}
	for _, m := range c.Messages {
		if m.AuthorID != user || m.ClientID != in.ClientID {
			continue
		}
		if m.Sequence <= member.From || m.Content != in.Content {
			return nil, mutationEvent{}, apiErrorf(409, "This message identity was already used")
		}
		return m, mutationEvent{}, nil
	}
	seq := uint64(len(c.Messages) + 1)
	m := core.ConversationMessage{ID: fmt.Sprintf("%s:%d", c.ID, seq), Sequence: seq, AuthorID: user, Content: in.Content, At: time.Now().UTC().Format(time.RFC3339Nano), ClientID: in.ClientID}
	c.Messages = append(c.Messages, m)
	c.Revision++
	member.Archived = false
	c.Members[user] = member
	return m, conversationMutation(mutationMessageSent, c.ID, m.ID), nil
}

func (s *Server) applyConversationSubroute(c *core.Conversation, member core.ConversationMember, user, method, action, rawBefore string, in conversationInput) (interface{}, mutationEvent, error) {
	switch action {
	case "messages":
		if member.Invited {
			return nil, mutationEvent{}, apiErrorf(403, "Accept the invitation to read or send messages")
		}
		if method == "GET" {
			out, err := conversationMessagesPage(c, member, rawBefore)
			return out, mutationEvent{}, err
		}
		if method != "POST" {
			return nil, mutationEvent{}, apiErrorf(405, "Method not allowed")
		}
		return appendLegacyMessage(c, member, user, in)
	case "membership":
		if method != "POST" {
			return nil, mutationEvent{}, apiErrorf(405, "Method not allowed")
		}
		out, changed, err := s.changeConversationMembership(c, user, in)
		var ev mutationEvent
		if err == nil && changed {
			ev = conversationMutation(mutationConversationMembership, c.ID, "")
		}
		return out, ev, err
	case "preferences":
		if method != "PATCH" {
			return nil, mutationEvent{}, apiErrorf(405, "Method not allowed")
		}
		out, err := s.conversationPreferences(c, user, in)
		if err != nil {
			return nil, mutationEvent{}, err
		}
		kind := mutationConversationUpdated
		if in.Refused != nil {
			kind = mutationConversationMembership
		}
		return out, conversationMutation(kind, c.ID, ""), nil
	default:
		return nil, mutationEvent{}, apiErrorf(404, "Conversation not found")
	}
}

func (s *Server) applyConversationRoute(user, method string, pieces []string, rawBefore string, in conversationInput) (interface{}, mutationEvent, error) {
	if _, err := s.forest.GetUserProfile(user); err != nil {
		return nil, mutationEvent{}, apiErrorf(401, "Account unavailable")
	}
	if len(pieces) == 1 {
		if method == "GET" {
			return s.listConversations(user), mutationEvent{}, nil
		}
		if method != "POST" {
			return nil, mutationEvent{}, apiErrorf(405, "Method not allowed")
		}
		c, created, err := s.createConversation(user, in)
		if err != nil {
			return nil, mutationEvent{}, err
		}
		var ev mutationEvent
		if created {
			ev = conversationMutation(mutationConversationCreated, c.ID, "")
		}
		return s.conversationView(c, user), ev, nil
	}
	if len(pieces) != 3 {
		return nil, mutationEvent{}, apiErrorf(404, "Conversation not found")
	}
	c := s.forest.Conversations[pieces[1]]
	if c == nil {
		return nil, mutationEvent{}, apiErrorf(404, "Conversation not found")
	}
	member, ok := c.Members[user]
	if !ok {
		return nil, mutationEvent{}, apiErrorf(404, "Conversation not found")
	}
	return s.applyConversationSubroute(c, member, user, method, pieces[2], rawBefore, in)
}

func (s *Server) handleConversations(w http.ResponseWriter, r *http.Request) {
	user, _ := userIDFrom(r)
	pieces := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	in, ok := decodeConversationBody(w, r, pieces)
	if !ok {
		return
	}
	rawBefore := r.URL.Query().Get("before")
	var result interface{}
	var announced mutationEvent
	var err error
	apply := func() error {
		result, announced, err = s.applyConversationRoute(user, r.Method, pieces, rawBefore, in)
		return err
	}
	if r.Method == "GET" {
		s.readForest(func() { err = apply() })
	} else {
		err = s.changeForest(apply)
	}
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if announced.Type != "" {
		s.publish(announced)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
