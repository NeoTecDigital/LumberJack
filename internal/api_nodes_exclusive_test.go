package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// POST /nodes with `If-None-Match: *`: create the node only if the last segment names nothing yet.
//
// The default route is idempotent, which is exactly what a client claiming a name cannot use: two
// concurrent claims are both answered 200 with the same node, and neither learns it lost. The
// condition makes the second one a 412, and the check sits in the same forest hold as the create, so
// of N concurrent conditional creates exactly one is the 200.

// postIfNoneMatch is `post` carrying an If-None-Match header. Like postAsync it touches no
// *testing.T, so a goroutine may call it.
func postIfNoneMatch(handler http.HandlerFunc, userID string, body map[string]interface{}, values ...string) *httptest.ResponseRecorder {
	encoded, _ := json.Marshal(body)

	request := httptest.NewRequest("POST", "/", bytes.NewBuffer(encoded))
	request.Header.Set("Content-Type", "application/json")
	for _, value := range values {
		request.Header.Add("If-None-Match", value)
	}
	request = request.WithContext(context.WithValue(request.Context(), "user_id", userID))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// decodeCreated reads a created-node answer, failing the test if it is not one.
func decodeCreated(t *testing.T, recorder *httptest.ResponseRecorder) NodeAnswer {
	t.Helper()

	var answer NodeAnswer
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatalf("The answer is not a created node: %v: %s", err, recorder.Body.String())
	}
	return answer
}

// lastMutation is the sequence of the newest mutation announced so far, as a cursor to poll after.
func lastMutation(t *testing.T, server *Server) uint64 {
	t.Helper()

	events, _ := server.pollMutations(0)
	if len(events) == 0 {
		t.Fatal("Nothing has been announced yet")
	}
	return events[len(events)-1].Sequence
}

// A conditional create of a fresh path is an ordinary create: the same 200, the same answer, and the
// missing ancestors made as branches on the way.
func TestExclusiveCreateOfAFreshPathAnswersAsAPlainCreate(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	recorder := postIfNoneMatch(server.handleCreateNode, userID, map[string]interface{}{"path": "work/claims/alpha"}, "*")
	if recorder.Code != http.StatusOK {
		t.Fatalf("Exclusive create: got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	node, err := server.getNodeFromPath("work/claims/alpha")
	if err != nil {
		t.Fatalf("Failed to find the created node: %v", err)
	}
	want := NodeAnswer{ID: node.ID, Name: "alpha", Path: "forest/work/claims/alpha", Type: leafNodeType}
	if answer := decodeCreated(t, recorder); answer != want {
		t.Errorf("Exclusive create answered %+v, want %+v", answer, want)
	}
	if _, err := server.getNodeFromPath("work/claims"); err != nil {
		t.Errorf("The missing ancestor was not created: %v", err)
	}
}

// A second conditional create of the same path is a 412 naming the canonical path, and changes and
// announces nothing — whatever type it asked for, since the condition is on the name.
func TestExclusiveCreateOfAnExistingPathIsRefused(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	body := map[string]interface{}{"path": "work/claims/alpha"}

	if code := postIfNoneMatch(server.handleCreateNode, userID, body, "*").Code; code != http.StatusOK {
		t.Fatalf("First exclusive create: got %d, want %d", code, http.StatusOK)
	}
	before := server.forestRevision()
	cursor := lastMutation(t, server)

	for _, nodeType := range []string{leafNodeType, branchNodeType} {
		body["type"] = nodeType
		refused := postIfNoneMatch(server.handleCreateNode, userID, body, "*")
		if refused.Code != http.StatusPreconditionFailed {
			t.Fatalf("Exclusive create of an existing %s: got %d, want %d", nodeType, refused.Code, http.StatusPreconditionFailed)
		}
		if !strings.Contains(refused.Body.String(), "forest/work/claims/alpha") {
			t.Errorf("The refusal does not name the existing path: %s", refused.Body.String())
		}
	}

	if server.forestRevision() != before {
		t.Error("A refused exclusive create changed the forest")
	}
	if events, _ := server.pollMutations(cursor); len(events) != 0 {
		t.Errorf("A refused exclusive create announced %d mutation(s)", len(events))
	}
}

// The condition is opt-in: without it a repeat of a conditional create is the idempotent default,
// answering the node that is already there.
func TestPlainCreateAfterAnExclusiveOneReturnsTheSameNode(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	body := map[string]interface{}{"path": "work/claims/alpha"}

	first := postIfNoneMatch(server.handleCreateNode, userID, body, "*")
	repeat := post(t, server.handleCreateNode, userID, body)
	if first.Code != http.StatusOK || repeat.Code != http.StatusOK {
		t.Fatalf("Exclusive then plain create: got %d and %d, want %d", first.Code, repeat.Code, http.StatusOK)
	}
	if first.Body.String() != repeat.Body.String() {
		t.Errorf("The plain repeat answered a different node:\n%s\n%s", first.Body.String(), repeat.Body.String())
	}
}

// Of concurrent conditional creates of one path, exactly one is the 200 and every other is a 412.
// A check made outside the hold would let several see the path empty and answer each of them 200.
func TestConcurrentExclusiveCreatesHaveExactlyOneWinner(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	const claimants = 32
	codes := make(chan int, claimants)

	var waiting sync.WaitGroup
	for claimant := 0; claimant < claimants; claimant++ {
		waiting.Add(1)
		go func() {
			defer waiting.Done()
			body := map[string]interface{}{"path": "work/claims/alpha"}
			codes <- postIfNoneMatch(server.handleCreateNode, userID, body, "*").Code
		}()
	}
	waiting.Wait()
	close(codes)

	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusPreconditionFailed] != claimants-1 {
		t.Fatalf("Concurrent exclusive creates answered %v, want 1 × 200 and %d × 412", counts, claimants-1)
	}

	parent, err := server.getNodeFromPath("work/claims")
	if err != nil {
		t.Fatalf("Failed to find the parent: %v", err)
	}
	if len(parent.Children) != 1 {
		t.Errorf("The parent holds %d children, want 1", len(parent.Children))
	}
}

// Any If-None-Match but a lone `*` names entity tags a node does not carry: a 400, and nothing made.
func TestExclusiveCreateRefusesAnyOtherIfNoneMatch(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	for _, values := range [][]string{{`"v1"`}, {`W/"v1"`}, {`*, "v1"`}, {"*", "*"}, {""}} {
		recorder := postIfNoneMatch(server.handleCreateNode, userID, map[string]interface{}{"path": "work"}, values...)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("If-None-Match %q: got %d, want %d", values, recorder.Code, http.StatusBadRequest)
		}
	}
	if len(server.forest.Children) != 0 {
		t.Errorf("A refused precondition created %d node(s)", len(server.forest.Children))
	}
}

// A caller who may not write the branch is refused for THAT, as without the condition: a 412 would
// tell it what the branch holds.
func TestExclusiveCreateWithoutPermissionIsForbiddenNotPreconditionFailed(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	body := map[string]interface{}{"path": "work"}

	if code := post(t, server.handleCreateNode, userID, body).Code; code != http.StatusOK {
		t.Fatalf("Create node: got %d, want %d", code, http.StatusOK)
	}
	if code := postIfNoneMatch(server.handleCreateNode, "someone-else", body, "*").Code; code != http.StatusForbidden {
		t.Errorf("Exclusive create as a stranger: got %d, want %d", code, http.StatusForbidden)
	}
}

// The embedded twin refuses the same way, with a Status an embedder can read.
func TestEmbeddedCreateNodeExclusiveRefusesAnExistingPath(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	request := CreateNodeRequest{Path: "work/claims/alpha"}

	if _, err := server.CreateNodeExclusive(userID, request); err != nil {
		t.Fatalf("First exclusive create: %v", err)
	}
	_, err := server.CreateNodeExclusive(userID, request)
	var refused *apiError
	if !asAPIError(err, &refused) || refused.Status() != http.StatusPreconditionFailed {
		t.Fatalf("Second exclusive create: got %v, want a %d", err, http.StatusPreconditionFailed)
	}
	if _, err := server.CreateNode(userID, request); err != nil {
		t.Errorf("A plain create of the same path: %v", err)
	}
}
