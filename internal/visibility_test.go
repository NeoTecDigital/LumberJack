// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/internal/compat"
)

// The visibility rule over every generic read (docs/extension-api.md §4.2): a node carrying the
// compatibility marker, a node carrying an extension's declared marker, and a node a filter hides
// are absent from all of them, and present to the extension's own read.

type secretFilter struct{}

func (secretFilter) Close(context.Context) error { return nil }

func (secretFilter) HiddenLocked(n *core.Node) bool { return n.Metadata["secret"] == true }

// hiddenFixture is a stock server with one visible record and three hidden ones, each owned by the
// admin so only the visibility rule can be what hides them.
func hiddenFixture(t *testing.T) (*Server, extension.Host, string, []*core.Node) {
	t.Helper()
	server, _ := newStockServer(t)
	var host extension.Host
	ext := testExtension{spec: extension.Spec{Name: "owner", Markers: []string{"test.owned/v1"}}, attach: func(h extension.Host) (extension.Instance, error) {
		host = h
		return secretFilter{}, nil
	}}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
	admin := adminID(t, server)
	var hidden []*core.Node
	err := plantAndPersist(server, func() error {
		for _, spec := range []struct {
			name    string
			receipt string
			secret  bool
		}{{"visible-record", "", false}, {"compat-owned", compat.OwnedScopeMarker, false}, {"extension-owned", "test.owned/v1", false}, {"filtered", "", true}} {
			node := core.NewNode(core.LeafNode, spec.name)
			node.Parents = map[string]string{server.forest.ID: server.forest.Name}
			node.CreatedBy = admin
			node.Metadata = map[string]interface{}{"title": spec.name + "-title"}
			if spec.secret {
				node.Metadata["secret"] = true
			}
			if spec.receipt != "" {
				node.CommandReceipts = map[string]interface{}{spec.receipt: map[string]interface{}{"owner": "x"}}
			}
			now := time.Now()
			node.Events = map[string]core.Event{spec.name + "-event": {StartTime: &now, Status: core.EventOngoing}}
			node.AddEntry(spec.name+"-entry", nil, admin, "", "")
			server.forest.Children[node.ID] = node
			if spec.name != "visible-record" {
				hidden = append(hidden, node)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, host, admin, hidden
}

func TestHiddenNodeIsAbsentFromEveryGenericRead(t *testing.T) {
	server, host, admin, hidden := hiddenFixture(t)
	bearer := sessionFor(t, server, admin, "admin")
	reads := map[string]string{
		"/forest":        body(t, server, bearer, "GET", "/forest", nil),
		"/forest/tree":   body(t, server, bearer, "GET", "/forest/tree", nil),
		"/query":         body(t, server, bearer, "POST", "/query", map[string]interface{}{"select": "nodes"}),
		"/query entries": body(t, server, bearer, "POST", "/query", map[string]interface{}{"select": "entries"}),
		"/aggregate":     body(t, server, bearer, "POST", "/aggregate", map[string]interface{}{"select": "events", "group": []string{"node_path"}, "metric": []string{"count"}}),
		"/events":        body(t, server, bearer, "GET", "/events", nil),
		"/entries":       body(t, server, bearer, "GET", "/entries", nil),
		"/changes":       strings.Join(changesVisible(t, server, bearer), ","),
	}
	if !strings.Contains(reads["/forest"], "visible-record") || !strings.Contains(reads["/events"], "visible-record-event") {
		t.Fatalf("the fixture's visible record is not visible: %s", reads["/forest"])
	}
	for _, node := range hidden {
		for route, answer := range reads {
			if strings.Contains(answer, node.Name) || strings.Contains(answer, node.ID) {
				t.Errorf("%s disclosed %s: %s", route, node.Name, answer)
			}
		}
		if code := bearerCall(t, server, bearer, "GET", "/nodes/"+node.Name, nil).Code; code == 200 {
			t.Errorf("GET /nodes/%s answered %d", node.Name, code)
		}
		server.updateCache()
		for attempt := 0; attempt < 2; attempt++ {
			server.forestMutex.RLock()
			_, err := server.getNodeFromPath(node.Name)
			server.forestMutex.RUnlock()
			if err == nil {
				t.Errorf("the path lookup (attempt %d, cache warm) reached %s", attempt, node.Name)
			}
		}
		preview := map[string]interface{}{"action": "grant", "path": node.Name, "username": "admin", "permission": 0, "scope": "item"}
		if code := bearerCall(t, server, bearer, "POST", "/access/preview", preview).Code; code == 200 {
			t.Errorf("/access/preview of %s answered %d", node.Name, code)
		}
	}
	assertOutboxCaptureSkipsHidden(t, server, host, admin, hidden)
	assertOwnerReadsItsNodes(t, host, hidden)
}

// bearerCall sends a request through the real router with a session bearer.
func bearerCall(t *testing.T, server *Server, bearer, method, target string, payload interface{}) *httptest.ResponseRecorder {
	t.Helper()
	encoded, _ := json.Marshal(payload)
	request := httptest.NewRequest(method, target, bytes.NewReader(encoded))
	request.Header.Set("Authorization", "Bearer "+bearer)
	return serve(t, server, request)
}

func body(t *testing.T, server *Server, bearer, method, target string, payload interface{}) string {
	t.Helper()
	response := bearerCall(t, server, bearer, method, target, payload)
	if response.Code != 200 {
		t.Fatalf("%s %s answered %d: %s", method, target, response.Code, response.Body.String())
	}
	return response.Body.String()
}

func changesVisible(t *testing.T, server *Server, bearer string) []string {
	t.Helper()
	var paths []string
	for _, path := range routeCall(t, server, bearer, "POST", "/changes", map[string]interface{}{"after": 0}, 200)["visible"].([]interface{}) {
		paths = append(paths, path.(string))
	}
	return paths
}

// A subscriber to a hidden node is told nothing when it changes: the outbox capture walk is a
// generic read too. The filtered node changes by an ordinary write and the extension's own node by
// its owner's write; the compatibility-owned node cannot change by either, which the guard holds.
func assertOutboxCaptureSkipsHidden(t *testing.T, server *Server, host extension.Host, admin string, hidden []*core.Node) {
	t.Helper()
	server.applicationHubEnabled.Store(true)
	if err := server.changeForest(func() error {
		for _, node := range hidden {
			server.subscribeLocked(node, admin, true)
		}
		server.correspondenceState().Pending = map[string]core.OutboxChange{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, node := range hidden {
		var err error
		switch node.Name {
		case "filtered":
			err = server.changeForest(func() error { node.Metadata["title"] = "changed"; return nil })
		case "extension-owned":
			_, err = host.Change(context.Background(), extension.WriteOp{Key: "own"}, func(extension.Tx) error {
				node.Metadata["title"] = "changed"
				return nil
			})
		}
		if err != nil {
			t.Fatalf("%s did not change: %v", node.Name, err)
		}
	}
	if pending := len(server.forest.Correspondence.Pending); pending != 0 {
		t.Fatalf("changes to hidden nodes queued %d notifications", pending)
	}
}

// The owner's own read is not filtered.
func assertOwnerReadsItsNodes(t *testing.T, host extension.Host, hidden []*core.Node) {
	t.Helper()
	if err := host.Read(func(tx extension.ReadTx) error {
		for _, node := range hidden {
			if _, err := tx.NodeByPath(node.Name); err != nil {
				t.Errorf("the owner could not read %s: %v", node.Name, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
