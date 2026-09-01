package internal

import (
	"fmt"
	"net/http"
	"testing"
)

// The two halves of the server agree about what a path is.
//
// THE DEFECT: POST /query answered node paths as `forest/momentum/x` while GET and PATCH
// /nodes/{path} answered 404 for that string and accepted only `momentum/x`. The `scope` parameter
// of /query behaved like the second and its results like the first, so /query's own output could
// not be fed back into /query. A client had to carry a translation layer between one route's output
// and another's input.
//
// The canonical form is the ROOTED one, and the reason is that it is TOTAL: the root is a real node
// that holds every user and is what a permission is granted on, and under the root-relative form
// its path is the empty string — which is not something a client can group on or link to. See
// node_path.go.

// Everything /query names can be fetched, re-scoped and re-created under that same name.
func TestEveryPathQueryEmitsIsAPathEveryRouteAccepts(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	leafFor(t, server, userID, "org/alpha/work")
	leafFor(t, server, userID, "org/beta/work")

	answer := queryOf(t, server, userID, map[string]interface{}{"select": "nodes"})
	paths := pathsOf(t, answer.Results)
	if len(paths) < 5 {
		t.Fatalf("Expected the root and four nodes under it, got %v", paths)
	}

	identities := map[string]string{}
	for _, result := range answer.Results {
		fields := result.(map[string]interface{})
		identities[fmt.Sprintf("%v", fields["path"])] = fmt.Sprintf("%v", fields["id"])
	}

	for _, path := range paths {
		// GET /nodes/{path} answers, and answers about the SAME node, under the SAME name.
		var answer map[string]interface{}
		decodeBody(t, serveRoute(t, server, "GET", "/nodes/"+path, userID, nil), &answer)

		node := answer["node"].(map[string]interface{})
		if got := fmt.Sprintf("%v", node["id"]); got != identities[path] {
			t.Errorf("GET /nodes/%s answered node %s, want %s", path, got, identities[path])
		}
		if got := fmt.Sprintf("%v", node["path"]); got != path {
			t.Errorf("GET /nodes/%s answered path %q, want %q", path, got, path)
		}

		// The same string is a SCOPE, and scoping to a node reports that node first.
		scoped := queryOf(t, server, userID, map[string]interface{}{"select": "nodes", "scope": path, "depth": 0})
		if scopedPaths := pathsOf(t, scoped.Results); len(scopedPaths) != 1 || scopedPaths[0] != path {
			t.Errorf("Scoping to %q reported %v, want exactly itself", path, scopedPaths)
		}
	}
}

// The root-relative form a client already has still resolves, on every route that takes a path.
func TestBothPathFormsNameTheSameNode(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	leafFor(t, server, userID, "org/alpha/work")

	for _, form := range []string{"org/alpha/work", "forest/org/alpha/work", "forest/org/alpha/work/"} {
		var answer map[string]interface{}
		decodeBody(t, serveRoute(t, server, "GET", "/nodes/"+form, userID, nil), &answer)

		node := answer["node"].(map[string]interface{})
		if got := fmt.Sprintf("%v", node["path"]); got != "forest/org/alpha/work" {
			t.Errorf("GET /nodes/%s answered path %q, want the canonical one", form, got)
		}
	}

	// And a path in the canonical form does not create a node named after the root when it is fed
	// back into the route that CREATES nodes.
	recorder := post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "forest/org/alpha/work"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /nodes with a canonical path: got %d, want %d: %s",
			recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if _, err := server.getNodeFromPath("forest/forest"); err == nil {
		t.Error("POST /nodes with a canonical path created a node named after the root")
	}

	// A node genuinely NAMED after the root is still reachable, because the canonical form has room
	// to say so.
	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": "forest/forest/nested", "type": "leaf",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create a node named after the root: got %d, want %d", code, http.StatusOK)
	}
	nested, err := server.getNodeFromPath("forest/forest/nested")
	if err != nil {
		t.Fatalf("A node named after the root was unreachable: %v", err)
	}
	if nested.Name != "nested" {
		t.Errorf("forest/forest/nested is %q, want nested", nested.Name)
	}
	if root, err := server.getNodeFromPath("forest"); err != nil || root != server.forest {
		t.Errorf("A bare %q no longer names the root: %v", "forest", err)
	}
}

// POST /nodes answers in the canonical form, and the stream announces the same string.
func TestNodeCreationAnswersTheCanonicalPath(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	var answer map[string]interface{}
	decodeBody(t, post(t, server.handleCreateNode, userID, map[string]interface{}{"path": "org/alpha"}), &answer)

	if answer["path"] != "forest/org/alpha" {
		t.Errorf("POST /nodes answered path %v, want forest/org/alpha", answer["path"])
	}
}
