// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/core"
	"net/http"
	"strings"
)

// messageOperationRoute must precede the legacy conversation dispatcher.
func messageOperationRoute(r *http.Request) bool {
	pieces := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pieces) < 3 || pieces[0] != "conversations" {
		return false
	}
	if pieces[2] == "attachments" {
		return true
	}
	return pieces[2] == "messages" && (len(pieces) > 3 || r.Method == "POST")
}
func (s *Server) handleMessageOperations(w http.ResponseWriter, r *http.Request) {
	user, ok := userIDFrom(r)
	if !ok {
		writeAPIError(w, apiErrorf(401, "Account unavailable"))
		return
	}
	pieces := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var in messageOperationInput
	var err error
	if r.Method != "GET" {
		in, err = messageInput(w, r)
	}
	if err != nil {
		writeAPIError(w, err)
		return
	}
	in, err = messageRequestScope(r, pieces, in)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	var result interface{}
	apply := func() error {
		if _, err := s.forest.GetUserProfile(user); err != nil {
			return apiErrorf(401, "Account unavailable")
		}
		c := s.forest.Conversations[pieces[1]]
		member, err := messageMember(c, user)
		if err != nil {
			return err
		}
		result, err = s.messageOperation(c, member, user, pieces, r.Method, in)
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
func (s *Server) messageOperation(c *core.Conversation, member core.ConversationMember, user string, pieces []string, method string, in messageOperationInput) (interface{}, error) {
	if pieces[2] == "attachments" {
		return s.messageAttachment(c, member, user, pieces, method, in)
	}
	if len(pieces) == 3 && method == "POST" {
		return s.messageSend(c, member, user, in)
	}
	if len(pieces) == 5 && pieces[4] == "history" && method == "GET" {
		if err := messageHistoryScope(c, member, pieces[3], in); err != nil {
			return nil, err
		}
		return messageHistory(c, member, pieces[3])
	}
	if len(pieces) == 4 && method == "PATCH" {
		return s.messageEdit(c, member, user, pieces[3], in)
	}
	return nil, apiErrorf(404, "Message operation not found")
}
func messageHistoryScope(c *core.Conversation, member core.ConversationMember, id string, in messageOperationInput) error {
	for _, m := range c.Messages {
		if m.ID != id || m.Sequence <= member.From || len(m.Envelope) == 0 {
			continue
		}
		return messageStoredScope(m.Context, in)
	}
	return nil
}
func messageHistory(c *core.Conversation, member core.ConversationMember, id string) (interface{}, error) {
	for _, m := range c.Messages {
		if m.ID != id || m.Sequence <= member.From {
			continue
		}
		history := append([]core.ConversationMessageEdit{}, m.EditEvidence...)
		history = append(history, messageEvidence(m))
		return map[string]interface{}{"message_id": id, "items": history}, nil
	}
	return nil, apiErrorf(404, "Message not found")
}

func messageRequestScope(r *http.Request, pieces []string, in messageOperationInput) (messageOperationInput, error) {
	if r.Method != "GET" && r.Method != "PATCH" && len(in.Envelope) == 0 && (in.Attachments == nil || len(*in.Attachments) == 0) && pieces[2] != "attachments" {
		return in, nil
	}
	account, workspace, err := AuthenticatedContentScope(r)
	if err != nil {
		if pieces[2] != "attachments" && len(in.Envelope) == 0 && (in.Attachments == nil || len(*in.Attachments) == 0) {
			return in, nil
		}
		return in, err
	}
	in.accountID = account
	in.workspaceID = workspace
	return in, nil
}
