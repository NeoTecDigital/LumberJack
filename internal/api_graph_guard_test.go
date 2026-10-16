// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/internal/graph"
)

// The graph is a subtree of the forest, and every route that writes a node by path could write it.
// QA rewrote an entity's kind with PATCH /nodes/…/metadata and removed every receipt with
// DELETE /nodes/…/_commands?mode=cascade. These tests hold every such route shut.

// graphWrite is one generic write aimed at a target path.
type graphWrite struct {
	name    string
	request func(target string) *http.Request
}

func jsonWrite(method, target string, body interface{}) *http.Request {
	encoded, _ := json.Marshal(body)
	return httptest.NewRequest(method, target, bytes.NewReader(encoded))
}

func uploadWrite(target string, fields map[string]string) *http.Request {
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for name, value := range fields {
		_ = form.WriteField(name, value)
	}
	part, _ := form.CreateFormFile("file", "note.txt")
	_, _ = part.Write([]byte("not the graph's"))
	_ = form.Close()
	request := httptest.NewRequest("POST", target, &body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	return request
}

// byPath are the routes that name ONE node, each aimed at the target it is given.
func byPath() []graphWrite {
	at := func(route, target string) string { return route + "?path=" + url.QueryEscape(target) }
	body := func(target string, more map[string]interface{}) map[string]interface{} {
		out := map[string]interface{}{"path": target}
		for name, value := range more {
			out[name] = value
		}
		return out
	}
	event := map[string]interface{}{"event_id": "e1", "content": "c", "start_time": "2030-01-01T00:00:00Z", "end_time": "2030-01-02T00:00:00Z"}
	work := func(command string) map[string]interface{} {
		return map[string]interface{}{"command": command, "client_id": "c-" + command, "title": "T", "kind": "idea", "status": "idea", "content": "c"}
	}
	post := func(name, route string, more map[string]interface{}) graphWrite {
		return graphWrite{name, func(target string) *http.Request { return jsonWrite("POST", route, body(target, more)) }}
	}
	query := func(name, method, route string, payload interface{}) graphWrite {
		return graphWrite{name, func(target string) *http.Request { return jsonWrite(method, at(route, target), payload) }}
	}
	return []graphWrite{
		{"node create beneath", func(target string) *http.Request { return jsonWrite("POST", "/nodes", body(target+"/made", nil)) }},
		{"metadata patch", func(target string) *http.Request {
			return jsonWrite("PATCH", "/nodes/"+target+"/metadata", map[string]interface{}{"graph.record": `{"kind":"forged"}`})
		}},
		{"node delete", func(target string) *http.Request { return jsonWrite("DELETE", "/nodes/"+target, nil) }},
		{"node delete cascade", func(target string) *http.Request { return jsonWrite("DELETE", "/nodes/"+target+"?mode=cascade", nil) }},
		post("entry create", "/entries", map[string]interface{}{"content": "forged"}),
		query("entry patch", "PATCH", "/entries/e1/metadata", map[string]interface{}{"metadata": map[string]string{"a": "b"}}),
		query("entry delete", "DELETE", "/entries/e1", nil),
		{"attachment upload", func(target string) *http.Request {
			return uploadWrite("/attachments/upload", map[string]string{"path": target})
		}},
		query("attachment delete", "DELETE", "/attachments/a1", nil),
		{"entry attachment", func(target string) *http.Request {
			return uploadWrite(at("/events/e1/entries/0/attachments", target), nil)
		}},
		post("event plan", "/events/plan", event),
		post("event start", "/events/start", event),
		post("event append", "/events/append", event),
		post("event end", "/events/end", event),
		query("event delete", "DELETE", "/events/e1", nil),
		query("event patch", "PATCH", "/events/e1", map[string]interface{}{"metadata": map[string]string{"a": "b"}}),
		post("time start", "/time/start", nil),
		post("time stop", "/time/stop", nil),
		query("time delete", "DELETE", "/time/s1", nil),
		post("work update", "/workspace/commands", work("update")),
		post("work log", "/workspace/commands", work("log")),
		post("work create", "/workspace/commands", work("create")),
	}
}

// byEdge are the two routes that name a PAIR of nodes, with the graph at either end.
func byEdge() []graphWrite {
	edge := func(method string, graphIsParent bool) func(string) *http.Request {
		return func(target string) *http.Request {
			pair := map[string]string{"parent_path": "work", "child_path": target}
			if graphIsParent {
				pair = map[string]string{"parent_path": target, "child_path": "work/n"}
			}
			return jsonWrite(method, "/nodes/link", pair)
		}
	}
	return []graphWrite{
		{"link a graph node elsewhere", edge("POST", false)},
		{"link a node beneath the graph", edge("POST", true)},
		{"unlink a graph node", edge("DELETE", false)},
		{"unlink beneath the graph", edge("DELETE", true)},
	}
}

func graphSend(server *Server, token string, request *http.Request) (int, string) {
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, request)
	return recorder.Code, recorder.Body.String()
}

// Item 1. Every generic write route refuses the graph root and everything beneath it — for the
// graph's own Admin, in either form of the path, and whether or not the node exists — and the
// forest is byte for byte what it was.
func TestGenericWriteRoutesRefuseTheGraph(t *testing.T) {
	server, _ := newGraphServer(t)
	token := graphAdmin(t, server)
	graphCall(t, server, token, "POST", "/nodes", map[string]string{"path": "work/n", "type": "leaf"})
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphSeed()); status != http.StatusOK {
		t.Fatalf("seed: %d %v", status, body)
	}
	targets := []string{
		"graph",
		"graph/" + graphScope,
		"graph/" + graphScope + "/" + graphTask,
		"graph/_commands",
		"graph/_commands/seed",
		"graph/_occurrences/" + graphOcc,
		"graph/absent",
		server.forest.Name + "/graph/_commands/seed",
	}
	before, _ := encodeState(server.forest)
	for _, write := range append(byPath(), byEdge()...) {
		for _, target := range targets {
			status, body := graphSend(server, token, write.request(target))
			if status != http.StatusForbidden || !strings.Contains(body, "belongs to the graph engine") {
				t.Errorf("%s on %s: %d %s", write.name, target, status, strings.TrimSpace(body))
			}
		}
	}
	if status, body := graphSend(server, token, jsonWrite("POST", "/nodes", map[string]string{"path": "graph"})); status != http.StatusForbidden {
		t.Errorf("node create of the graph root itself: %d %s", status, body)
	}
	after, _ := encodeState(server.forest)
	if !bytes.Equal(before, after) {
		t.Fatal("a refused generic write changed the forest")
	}
	if status, snapshot := graphCall(t, server, token, "GET", "/graph", nil); status != http.StatusOK || snapshot["revision"].(float64) != 1 {
		t.Fatalf("the graph after the refusals: %d %v", status, snapshot)
	}
	if status, body := graphCall(t, server, token, "POST", "/graph/commands", graphSeed()); status != http.StatusOK || body["replayed"] != true {
		t.Fatalf("the seed's receipt did not survive the refusals: %d %v", status, body)
	}
}

// The generic routes may not CREATE the graph root either: before the first command there is no
// node to refuse, only the name, and a root made by POST /nodes would inherit the forest's users.
func TestGenericRoutesCannotCreateTheGraphRoot(t *testing.T) {
	server, _ := newGraphServer(t)
	token := graphAdmin(t, server)
	for _, path := range []string{"graph", "graph/_commands/forged", server.forest.Name + "/graph"} {
		if status, body := graphSend(server, token, jsonWrite("POST", "/nodes", map[string]string{"path": path, "type": "branch"})); status != http.StatusForbidden {
			t.Fatalf("POST /nodes %s: %d %s", path, status, body)
		}
	}
	if graph.Root(server.forest) != nil {
		t.Fatal("a generic route created the graph root")
	}
}

// Item 1. The graph root lists the principal whose command created it, with Admin, and no one
// else: Write on the forest root is not Write — or Read — on the graph, in either direction.
func TestGraphRootIsCreatedForItsCreatorOnly(t *testing.T) {
	server, _ := newGraphServer(t)
	writer := core.User{ID: core.GenerateUserID(), Username: "writer"}
	if err := server.forest.AssignUser(writer, core.WritePermission); err != nil {
		t.Fatal(err)
	}
	admin, writerToken := graphAdmin(t, server), sessionFor(t, server, writer.ID, writer.Username)
	if status, body := graphCall(t, server, writerToken, "POST", "/graph/commands", graphSeed()); status != http.StatusOK {
		t.Fatalf("a writer of the forest root could not create the graph: %d %v", status, body)
	}
	root := graph.Root(server.forest)
	if len(root.Users) != 1 || root.Users[0].ID != writer.ID || root.Users[0].Username != "writer" || root.Users[0].Password != "" ||
		len(root.Users[0].Permissions) != 1 || root.Users[0].Permissions[0] != core.AdminPermission || root.CreatedBy != writer.ID {
		t.Fatalf("graph root users = %+v, created by %q", root.Users, root.CreatedBy)
	}
	if len(server.forest.Users) < 2 || !server.forest.CheckPermission(adminUserID(t, server), core.AdminPermission) {
		t.Fatal("the test needs a forest Admin who did not create the graph")
	}
	routes := []struct {
		method, target string
		body           interface{}
	}{{"POST", "/graph/commands", graphMove("m", 1, 1)}, {"GET", "/graph", nil}, {"GET", "/graph/events", nil}, {"GET", "/graph/commands/seed", nil}}
	for _, route := range routes {
		if status, body := graphCall(t, server, admin, route.method, route.target, route.body); status != http.StatusForbidden {
			t.Fatalf("%s %s by a forest Admin who is not on the graph: %d %v", route.method, route.target, status, body)
		}
	}
	if status, body := graphCall(t, server, writerToken, "POST", "/graph/commands", graphMove("m", 1, 1)); status != http.StatusOK || body["revision"].(float64) != 2 {
		t.Fatalf("the creator's own command: %d %v", status, body)
	}
}

// The same rule from the other side, as QA will ask it: a user holding Write on the forest root
// and nothing on `graph` is answered 403.
func TestForestWriterWithoutGraphAccessIsForbidden(t *testing.T) {
	server, _ := newGraphServer(t)
	admin := graphAdmin(t, server)
	if status, body := graphCall(t, server, admin, "POST", "/graph/commands", graphSeed()); status != http.StatusOK {
		t.Fatalf("seed: %d %v", status, body)
	}
	writer := core.User{ID: core.GenerateUserID(), Username: "writer"}
	if err := server.forest.AssignUser(writer, core.WritePermission); err != nil {
		t.Fatal(err)
	}
	token := sessionFor(t, server, writer.ID, writer.Username)
	if status, _ := graphCall(t, server, token, "POST", "/nodes", map[string]string{"path": "work/mine", "type": "leaf"}); status != http.StatusOK {
		t.Fatalf("the writer cannot write the forest root at all: %d", status)
	}
	status, body := graphCall(t, server, token, "POST", "/graph/commands", graphMove("m", 1, 1))
	if status != http.StatusForbidden || body["error"].(map[string]interface{})["code"] != "forbidden" {
		t.Fatalf("a forest writer with nothing on graph commanded it: %d %v", status, body)
	}
	if status, _ := graphCall(t, server, token, "GET", "/graph", nil); status != http.StatusForbidden {
		t.Fatalf("a forest writer with nothing on graph read it: %d", status)
	}
	if status, snapshot := graphCall(t, server, admin, "GET", "/graph", nil); status != http.StatusOK || snapshot["revision"].(float64) != 1 {
		t.Fatalf("the refused command changed the graph: %d %v", status, snapshot)
	}
}

func adminUserID(t *testing.T, server *Server) string {
	t.Helper()
	for _, user := range server.forest.Users {
		if user.Username == "admin" {
			return user.ID
		}
	}
	t.Fatal("no admin account")
	return ""
}
