package internal

import (
	"bytes"
	"encoding/json"
	"github.com/NeoTecDigital/LumberJack/internal/core"
	"net/http/httptest"
	"testing"
	"time"
)

func workTestCommand(t *testing.T, server *Server, user string, cmd workCommand, status int) map[string]interface{} {
	t.Helper()
	raw, _ := json.Marshal(cmd)
	req := withUser(httptest.NewRequest("POST", "/workspace/commands", bytes.NewReader(raw)), user)
	rec := httptest.NewRecorder()
	server.handleWorkCommand(rec, req)
	if rec.Code != status {
		t.Fatalf("%s: status %d, want %d: %s", cmd.Command, rec.Code, status, rec.Body.String())
	}
	var result map[string]interface{}
	if status == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func TestWorkspaceMultiuserCommands(t *testing.T) {
	server := setupTestForest(t)
	server.forest.Users = append(server.forest.Users, core.User{ID: "bob", Username: "bob", Permissions: []core.Permission{core.ReadPermission}})
	cmd := workCommand{Command: "create", Path: "root", ClientID: "create-goal", Title: "Shared goal", Kind: "goal"}
	answer := workTestCommand(t, server, "admin", cmd, 200)
	path := answer["path"].(string)
	private, _ := server.getNodeFromPath(path)
	if private.CheckPermission("bob", core.ReadPermission) {
		t.Fatal("root account inventory was inherited into private work")
	}
	same := workTestCommand(t, server, "admin", cmd, 200)
	if same["path"] != path {
		t.Fatal("retry created another node")
	}
	cmd.Title = "Different payload"
	workTestCommand(t, server, "admin", cmd, 409)
	workTestCommand(t, server, "bob", workCommand{Command: "log", Path: path, ClientID: "denied", Content: "no"}, 403)
	edit := 1
	workTestCommand(t, server, "admin", workCommand{Command: "share", Path: path, ClientID: "grant", Username: "bob", Permission: &edit}, 200)
	log := workCommand{Command: "log", Path: path, ClientID: "bob-message", Content: "Progress from Bob"}
	workTestCommand(t, server, "bob", log, 200)
	workTestCommand(t, server, "bob", log, 200)
	node, _ := server.getNodeFromPath(path)
	if len(node.Entries) != 1 || node.Entries[0].UserID != "bob" {
		t.Fatal("log not exactly once and attributed")
	}
	revision := workRevision(node)
	update := workCommand{Command: "update", Path: path, ClientID: "edit-1", Revision: revision, Title: "Updated", Kind: "goal", Status: "active"}
	workTestCommand(t, server, "admin", update, 200)
	update.ClientID = "stale-edit"
	workTestCommand(t, server, "bob", update, 409)
	timer := workTestCommand(t, server, "bob", workCommand{Command: "timer_start", Path: path, ClientID: "start"}, 200)
	workTestCommand(t, server, "bob", workCommand{Command: "timer_start", Path: path, ClientID: "second-start"}, 409)
	entryID := timer["result"].(map[string]interface{})["id"].(string)
	workTestCommand(t, server, "bob", workCommand{Command: "timer_stop", Path: path, ClientID: "stop", EventID: entryID}, 200)
	workTestCommand(t, server, "bob", workCommand{Command: "timer_stop", Path: path, ClientID: "second-stop", EventID: entryID}, 409)
	remove := -1
	workTestCommand(t, server, "admin", workCommand{Command: "share", Path: path, ClientID: "revoke", Username: "bob", Permission: &remove}, 200)
	workTestCommand(t, server, "bob", workCommand{Command: "log", Path: path, ClientID: "after-revoke", Content: "no"}, 403)
	rec := httptest.NewRecorder()
	server.handleWorkspace(rec, withUser(httptest.NewRequest("GET", "/workspace", nil), "bob"))
	if bytes.Contains(rec.Body.Bytes(), []byte("Progress from Bob")) || bytes.Contains(rec.Body.Bytes(), []byte("command_receipts")) {
		t.Fatal("snapshot leaked revoked work or internal receipts")
	}
	// Idempotency survives the datastore codec, including acknowledged response identities.
	encoded, err := encodeState(server.forest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte("command_receipts")) {
		t.Fatal("retry receipts were not persisted")
	}
}

func TestWorkspaceRunSnapshotsNestedDefinition(t *testing.T) {
	server := setupTestForest(t)
	create := func(path, title, kind, id string) string {
		return workTestCommand(t, server, "admin", workCommand{Command: "create", Path: path, Title: title, Kind: kind, ClientID: id}, 200)["path"].(string)
	}
	procedure := create("root", "Release", "procedure", "p")
	group := create(procedure, "Prepare", "action", "g")
	leaf := create(group, "Review", "action", "l")
	answer := workTestCommand(t, server, "admin", workCommand{Command: "run", Path: "root", TemplatePath: procedure, ClientID: "run"}, 200)
	runID := answer["result"].(map[string]interface{})["id"].(string)
	run := server.forest.Children[runID]
	if run == nil || len(run.Children) != 1 {
		t.Fatal("run did not instantiate steps")
	}
	steps := childrenByName(run)
	if len(steps[0].Children) != 1 {
		t.Fatal("nested step missing")
	}
	original, _ := server.getNodeFromPath(leaf)
	original.Metadata["description"] = "later edit"
	copied := childrenByName(steps[0])[0]
	if copied.Metadata["description"] == "later edit" {
		t.Fatal("template edit changed existing run")
	}
	second := workTestCommand(t, server, "admin", workCommand{Command: "run", Path: "root", TemplatePath: procedure, ClientID: "run-2"}, 200)
	secondRun := server.forest.Children[second["result"].(map[string]interface{})["id"].(string)]
	if secondRun.Metadata["procedure_revision"] == run.Metadata["procedure_revision"] {
		t.Fatal("nested template changes must change definition version")
	}
}

func TestWorkspaceDefaultsArePrivateAndIdempotent(t *testing.T) {
	server := setupTestForest(t)
	server.forest.Users = append(server.forest.Users, core.User{ID: "bob", Username: "bob", Permissions: []core.Permission{core.ReadPermission}})
	cmd := workCommand{Command: "initialize", Path: "root", ClientID: "initialize-bob"}
	answer := workTestCommand(t, server, "bob", cmd, 200)
	id := answer["result"].(map[string]interface{})["id"].(string)
	cmd.ClientID = "another-device"
	second := workTestCommand(t, server, "bob", cmd, 200)
	if second["result"].(map[string]interface{})["id"] != id {
		t.Fatal("two devices created two private workspaces")
	}
	home := server.forest.Children[id]
	if len(home.Children) != 4 || !home.CheckPermission("bob", core.AdminPermission) || home.CheckPermission("admin", core.ReadPermission) {
		t.Fatal("default workspace is incomplete or not private")
	}
	for _, child := range home.Children {
		if child.CheckPermission("admin", core.ReadPermission) {
			t.Fatal("default collection inherited account inventory")
		}
	}
}

func TestWorkspaceBoardTransitionsPreserveHistory(t *testing.T) {
	server := setupTestForest(t)
	node, _ := server.getNodeFromPath("root/test-node")
	start, end := time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
	if err := node.PlanEvent("plan", "admin", &start, &end, map[string]interface{}{"title": "Keep this title"}); err != nil {
		t.Fatal(err)
	}
	planned := node.PlannedEvents["plan"]
	planned.Realizes = node.ID
	planned.AssignedTo = "admin"
	node.PlannedEvents["plan"] = planned
	for _, status := range []string{"pending", "ongoing", "finished"} {
		workTestCommand(t, server, "admin", workCommand{Command: "event_transition", Path: "root/test-node", ClientID: status, EventID: "plan", Status: status}, 200)
		event := node.Events["plan"]
		if string(event.Status) != status || event.Metadata["title"] != "Keep this title" || event.Realizes != node.ID {
			t.Fatal("transition discarded event identity or context")
		}
		if status == "pending" && event.StartTime != nil {
			t.Fatal("queueing started the event clock")
		}
	}
	workTestCommand(t, server, "admin", workCommand{Command: "event_transition", Path: "root/test-node", ClientID: "backwards", EventID: "plan", Status: "ongoing"}, 409)
}
