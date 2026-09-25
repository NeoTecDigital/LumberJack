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
	Kind           string   `json:"kind,omitempty"`
	Title          string   `json:"title,omitempty"`
	ProjectPath    string   `json:"project_path,omitempty"`
	Usernames      []string `json:"usernames,omitempty"`
	ClientID       string   `json:"client_id,omitempty"`
	Content        string   `json:"content,omitempty"`
	Action         string   `json:"action,omitempty"`
	Username       string   `json:"username,omitempty"`
	IncludeHistory bool     `json:"include_history,omitempty"`
	ReadThrough    *uint64  `json:"read_through,omitempty"`
	Muted          *bool    `json:"muted,omitempty"`
	Archived       *bool    `json:"archived,omitempty"`
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
func (s *Server) conversationView(c *core.Conversation, user string) map[string]interface{} {
	own := c.Members[user]
	unread := 0
	var preview interface{}
	if !own.Invited {
		for _, m := range c.Messages {
			if m.Sequence > own.From {
				preview = m
				if m.Sequence > own.ReadThrough && m.AuthorID != user {
					unread++
				}
			}
		}
	}
	people := []map[string]interface{}{}
	for id, m := range c.Members {
		people = append(people, map[string]interface{}{"id": id, "username": s.conversationUsername(id), "invited": m.Invited, "owner": id == c.OwnerID})
	}
	sort.Slice(people, func(i, j int) bool { return people[i]["id"].(string) < people[j]["id"].(string) })
	// Project association conveys no entitlement to the project or its title.
	return map[string]interface{}{"id": c.ID, "kind": c.Kind, "title": c.Title, "project_id": c.ProjectID, "revision": c.Revision, "members": people, "invited": own.Invited, "muted": own.Muted, "archived": own.Archived, "unread": unread, "last_message": preview, "read_through": own.ReadThrough, "history_from": own.From}
}
func (s *Server) handleConversations(w http.ResponseWriter, r *http.Request) {
	user, _ := userIDFrom(r)
	pieces := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var in conversationInput
	if r.Method != "GET" {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&in) != nil {
			http.Error(w, "Invalid conversation request", 400)
			return
		}
		var trailing interface{}
		if decoder.Decode(&trailing) != io.EOF {
			http.Error(w, "Provide one complete conversation request", 400)
			return
		}
	}
	if r.Method != "GET" {
		if err := validateConversationInput(pieces, r.Method, in); err != nil {
			writeAPIError(w, err)
			return
		}
	}
	var result interface{}
	var err error
	apply := func() error {
		if _, err := s.forest.GetUserProfile(user); err != nil {
			return apiErrorf(401, "Account unavailable")
		}
		if len(pieces) == 1 {
			if r.Method == "GET" {
				items := []map[string]interface{}{}
				for _, c := range s.forest.Conversations {
					if _, ok := c.Members[user]; ok {
						items = append(items, s.conversationView(c, user))
					}
				}
				sort.Slice(items, func(i, j int) bool { return items[i]["id"].(string) < items[j]["id"].(string) })
				result = map[string]interface{}{"items": items}
				return nil
			}
			if r.Method != "POST" {
				return apiErrorf(405, "Method not allowed")
			}
			c, err := s.createConversation(user, in)
			if err != nil {
				return err
			}
			result = s.conversationView(c, user)
			return nil
		}
		if len(pieces) != 3 {
			return apiErrorf(404, "Conversation not found")
		}
		c := s.forest.Conversations[pieces[1]]
		if c == nil {
			return apiErrorf(404, "Conversation not found")
		}
		member, ok := c.Members[user]
		if !ok {
			return apiErrorf(404, "Conversation not found")
		}
		switch pieces[2] {
		case "messages":
			if member.Invited {
				return apiErrorf(403, "Accept the invitation to read or send messages")
			}
			if r.Method == "GET" {
				before := uint64(len(c.Messages) + 1)
				if raw := r.URL.Query().Get("before"); raw != "" {
					n, e := strconv.ParseUint(raw, 10, 64)
					if e != nil || n == 0 {
						return apiErrorf(400, "Invalid message cursor")
					}
					before = n
				}
				items := []core.ConversationMessage{}
				for i := len(c.Messages) - 1; i >= 0 && len(items) < 50; i-- {
					m := c.Messages[i]
					if m.Sequence < before && m.Sequence > member.From {
						items = append(items, m)
					}
				}
				sort.Slice(items, func(i, j int) bool { return items[i].Sequence < items[j].Sequence })
				var next interface{}
				if len(items) == 50 && items[0].Sequence > member.From+1 {
					next = items[0].Sequence
				}
				result = map[string]interface{}{"items": items, "next_before": next}
				return nil
			}
			if r.Method != "POST" {
				return apiErrorf(405, "Method not allowed")
			}
			if strings.TrimSpace(in.Content) == "" || len(in.Content) > 65536 || len(in.ClientID) < 1 || len(in.ClientID) > 100 {
				return apiErrorf(400, "Write a message of up to 65536 bytes")
			}
			for _, m := range c.Messages {
				if m.AuthorID == user && m.ClientID == in.ClientID {
					if m.Sequence <= member.From || m.Content != in.Content {
						return apiErrorf(409, "This message identity was already used")
					}
					result = m
					return nil
				}
			}
			seq := uint64(len(c.Messages) + 1)
			m := core.ConversationMessage{ID: fmt.Sprintf("%s:%d", c.ID, seq), Sequence: seq, AuthorID: user, Content: in.Content, At: time.Now().UTC().Format(time.RFC3339Nano), ClientID: in.ClientID}
			c.Messages = append(c.Messages, m)
			c.Revision++
			member.Archived = false
			c.Members[user] = member
			result = m
			return nil
		case "membership":
			if r.Method != "POST" {
				return apiErrorf(405, "Method not allowed")
			}
			result, err = s.changeConversationMembership(c, user, in)
			return err
		case "preferences":
			if r.Method != "PATCH" {
				return apiErrorf(405, "Method not allowed")
			}
			if in.ReadThrough != nil {
				if member.Invited {
					return apiErrorf(403, "Accept the invitation before changing a message read position")
				}
				if *in.ReadThrough > uint64(len(c.Messages)) {
					return apiErrorf(400, "Read position exceeds conversation")
				}
				member.ReadThrough = *in.ReadThrough
			}
			if in.Muted != nil {
				member.Muted = *in.Muted
			}
			if in.Archived != nil {
				member.Archived = *in.Archived
			}
			c.Members[user] = member
			result = s.conversationView(c, user)
			return nil
		default:
			return apiErrorf(404, "Conversation not found")
		}
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
