package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// A node handed out of the forest hold is a node another request is free to be writing.
//
// handleCreateNode read node.ID, node.Name and node.Type to build its answer AFTER changeForest had
// released the exclusive hold. core.(*Node).promoteToBranch writes n.Type, and it runs under
// ANOTHER request's hold — so two ordinary POST /nodes, one making `work/nN` a leaf and one making
// `work/nN/c` beneath it, are a write to Type against a read of Type with nothing between them.
//
// This is the same class as the aliasing the projection carried: the layer that answers and the
// layer that changes disagree about who owns the object.

// postAsync is `post` for a goroutine: it touches no *testing.T, because Fatalf from anywhere but
// the test's own goroutine does not stop the test and does not report where it came from.
func postAsync(handler http.HandlerFunc, userID string, body map[string]interface{}) int {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0
	}

	request := httptest.NewRequest("POST", "/", bytes.NewBuffer(encoded))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), "user_id", userID))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

// Two concurrent POST /nodes against a path and a path beneath it race on nothing.
func TestConcurrentNodeCreationDoesNotRaceOnTheAnswer(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": "work", "type": "branch",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create work: got %d, want %d", code, http.StatusOK)
	}

	const pairs = 64

	var waiting sync.WaitGroup
	for pair := 0; pair < pairs; pair++ {
		leaf := fmt.Sprintf("work/n%d", pair)
		child := leaf + "/c"

		waiting.Add(2)
		go func() {
			defer waiting.Done()
			postAsync(server.handleCreateNode, userID, map[string]interface{}{"path": leaf})
		}()
		go func() {
			defer waiting.Done()
			postAsync(server.handleCreateNode, userID, map[string]interface{}{"path": child})
		}()
	}
	waiting.Wait()
}
