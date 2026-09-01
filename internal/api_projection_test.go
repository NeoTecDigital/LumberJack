package internal

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// What a route may never emit, and the shape of the forest it has to survive emitting.
//
// core.User carries a bcrypt hash tagged `json:"password"`, and core.Attachment carries the file's
// bytes tagged `json:"data"`. A node view used to embed core.Event, core.Entry and core.Attachment
// WHOLE, so every listing of the forest shipped every file anyone had ever uploaded to anyone who
// could read any part of the tree.

// secretMarkers are the strings a response must never contain: the field names that carry a hash or
// a file, and a payload planted in the fixture so a match cannot be a coincidence.
const plantedAttachmentBody = "planted-attachment-body-not-for-any-listing"

// plantSecrets puts a real password hash and a real attachment where a careless projection would
// find them.
func plantSecrets(t *testing.T, server *Server, path string) {
	t.Helper()

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the fixture node: %v", err)
	}

	attachment := core.Attachment{
		ID:         "planted",
		Name:       "planted.txt",
		Type:       "text/plain",
		Size:       int64(len(plantedAttachmentBody)),
		Data:       []byte(plantedAttachmentBody),
		UploadedAt: time.Now(),
	}
	node.Attachments = map[string]core.Attachment{attachment.ID: attachment}
	node.Entries = append(node.Entries, core.Entry{
		Content:     "an entry that carries a file",
		Attachments: []core.Attachment{attachment},
	})

	event := node.Events["planted-event"]
	event.Status = core.EventOngoing
	event.Entries = append(event.Entries, core.Entry{
		Content:     "an event entry that carries a file",
		Attachments: []core.Attachment{attachment},
	})
	node.Events["planted-event"] = event
}

// assertNoSecrets fails on anything that should never have left the process.
func assertNoSecrets(t *testing.T, route string, body string) {
	t.Helper()

	// The BASE64 of the planted body, not the body itself: []byte is encoded, so asserting on the
	// plain text is an assertion that can never fire — a vacuous guard reads exactly like a passing
	// one.
	for _, forbidden := range []string{
		base64.StdEncoding.EncodeToString([]byte(plantedAttachmentBody)),
		`"password"`,
		`"data"`,
		"$2a$", // the prefix of every bcrypt hash this server writes
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("%s emitted %q", route, forbidden)
		}
	}
}

// No route that lists the forest emits a password hash or the bytes of an attachment.
func TestListingRoutesEmitNoSecrets(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/secrets")

	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": path, "event_id": "planted-event",
	}).Code; code != http.StatusOK {
		t.Fatalf("Start event: got %d, want %d", code, http.StatusOK)
	}
	plantSecrets(t, server, path)

	assertNoSecrets(t, "GET /forest", get(t, server.handleGetForest, userID, "/forest").Body.String())
	assertNoSecrets(t, "GET /users", get(t, server.handleGetUsers, userID, "/users").Body.String())
	assertNoSecrets(t, "GET /forest/tree",
		get(t, server.handleGetTree, userID, "/forest/tree?path="+path).Body.String())
	assertNoSecrets(t, "POST /events", post(t, server.handleGetEventEntries, userID, map[string]interface{}{
		"path": path, "event_id": "planted-event",
	}).Body.String())
}

// A projection of the forest still says what a client needs, so the assertion above is not passing
// because the answer is empty.
func TestForestListingStillCarriesWhatAClientNeeds(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/present")

	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": path, "event_id": "visible-event",
	}).Code; code != http.StatusOK {
		t.Fatalf("Start event: got %d, want %d", code, http.StatusOK)
	}
	plantSecrets(t, server, path)

	body := get(t, server.handleGetForest, userID, "/forest").Body.String()
	for _, expected := range []string{"visible-event", "planted.txt", `"uploaded_at"`, `"username"`} {
		if !strings.Contains(body, expected) {
			t.Errorf("GET /forest dropped %q along with the secrets", expected)
		}
	}
}

// A node reachable by two paths is projected on both, and a CYCLE terminates.
//
// The forest is a multi-parent DAG. Plain recursion down Children never returns once an edge closes
// a loop, so the route that lists the forest would hang the request and grow without bound.
func TestForestProjectionSurvivesAMultiParentCycle(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	leafFor(t, server, userID, "work/left/shared")
	leafFor(t, server, userID, "work/right")

	shared, err := server.getNodeFromPath("work/left/shared")
	if err != nil {
		t.Fatalf("Failed to find the shared node: %v", err)
	}
	right, err := server.getNodeFromPath("work/right")
	if err != nil {
		t.Fatalf("Failed to find the second parent: %v", err)
	}
	work, err := server.getNodeFromPath("work")
	if err != nil {
		t.Fatalf("Failed to find the root of the fixture: %v", err)
	}

	// A second parent for the shared node, and then an edge back up to make a cycle.
	right.Type = core.BranchNode
	right.Children[shared.ID] = shared
	shared.AddParent(right)
	shared.Type = core.BranchNode
	shared.Children[work.ID] = work
	work.AddParent(shared)

	done := make(chan string, 1)
	go func() {
		done <- get(t, server.handleGetForest, userID, "/forest").Body.String()
	}()

	select {
	case body := <-done:
		var decoded map[string]interface{}
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatalf("GET /forest over a cyclic DAG did not answer JSON: %v", err)
		}
		if !strings.Contains(body, `"shared"`) {
			t.Error("GET /forest dropped the shared node")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("GET /forest did not terminate over a cyclic DAG")
	}
}
