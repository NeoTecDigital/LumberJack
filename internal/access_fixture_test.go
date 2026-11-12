// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
)

// The record fixtures the access and stream tests set up with. They write, through the engine's own
// write path, the state the retired workspace commands wrote for the same operations: a child record
// its creator alone holds, a logged entry, a subscription. The tests' assertions are about access and
// the stream, which the fixtures do not change.

type recordCommand struct {
	Command    string // "create", "log" or "subscribe"
	Path       string
	ClientID   string
	Title      string
	Kind       string
	Content    string
	Subscribed bool
}

// recordTestCommand runs one fixture operation as user and checks the status it answers.
func recordTestCommand(t *testing.T, server *Server, user string, cmd recordCommand, status int) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	err := server.changeNode(cmd.Path, user, recordPermission(cmd.Command), func(node *core.Node) error {
		var err error
		result, err = server.applyRecordCommand(node, user, cmd)
		return err
	})
	if err == nil {
		server.publish(mutation(recordMutation(cmd.Command), server.canonicalPath(cmd.Path)))
	}
	got := http.StatusOK
	var failure *apiError
	if asAPIError(err, &failure) {
		got = failure.status
	} else if err != nil {
		got = http.StatusInternalServerError
	}
	if got != status {
		t.Fatalf("%s %s: status %d, want %d: %v", cmd.Command, cmd.Path, got, status, err)
	}
	return result
}

// recordMutation is the stream event each fixture operation publishes, as the routes that make the
// same change do.
func recordMutation(command string) string {
	switch command {
	case "create":
		return mutationNodeCreated
	case "log":
		return mutationEntryAdded
	}
	return mutationMetadataSet
}

func recordPermission(command string) core.Permission {
	if command == "subscribe" {
		return core.ReadPermission
	}
	return core.WritePermission
}

func (server *Server) applyRecordCommand(node *core.Node, user string, cmd recordCommand) (map[string]interface{}, error) {
	switch cmd.Command {
	case "create":
		child, err := node.AddChildNode("record-"+core.GenerateEntryID(), core.BranchNode, user)
		if err != nil {
			return nil, apiErrorf(http.StatusBadRequest, "%v", err)
		}
		child.Kind = cmd.Kind
		child.Users = []core.User{{ID: user, Permissions: []core.Permission{core.AdminPermission}}}
		child.Metadata = map[string]interface{}{"title": cmd.Title, "status": "idea", "intent_id": node.ID, "description": cmd.Content}
		server.subscribeLocked(child, user, true)
		return map[string]interface{}{"id": child.ID, "path": server.canonicalPath(cmd.Path) + "/" + child.Name}, nil
	case "log":
		entry := node.AddEntry(cmd.Content, map[string]interface{}{"client_id": cmd.ClientID, "category": "log"}, user, "", "")
		return map[string]interface{}{"id": entry.ID}, nil
	case "subscribe":
		server.subscribeLocked(node, user, cmd.Subscribed)
		return map[string]interface{}{"subscribed": cmd.Subscribed}, nil
	}
	return nil, apiErrorf(http.StatusBadRequest, "unknown fixture command %q", cmd.Command)
}

func (server *Server) subscribeLocked(node *core.Node, user string, subscribed bool) {
	if user == SystemUserID {
		return
	}
	if server.forest.Subscriptions == nil {
		server.forest.Subscriptions = map[string]map[string]bool{}
	}
	if server.forest.Subscriptions[user] == nil {
		server.forest.Subscriptions[user] = map[string]bool{}
	}
	server.forest.Subscriptions[user][node.ID] = subscribed
}

// routeCall sends one request through the application transport with a bearer and checks its status.
func routeCall(t *testing.T, s *Server, token, method, path string, body interface{}, status int) map[string]interface{} {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := s.ApplicationCall(ApplicationRequest{Method: method, Target: path, Headers: map[string]string{"Authorization": "Bearer " + token}, Body: raw})
	if r.Status != status {
		t.Fatalf("%s %s: wanted %d got %d: %s", method, path, status, r.Status, r.Body)
	}
	if status != 200 {
		return nil
	}
	return decodeApplication(t, r)
}
