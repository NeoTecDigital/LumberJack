package internal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
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

// findNodeView finds a node's view inside a forest document, wherever the projection put it.
func findNodeView(view nodeView, id string) (nodeView, bool) {
	if view.ID == id {
		return view, true
	}
	for _, child := range view.Children {
		if found, ok := findNodeView(child, id); ok {
			return found, ok
		}
	}
	return nodeView{}, false
}

// A projection may not point back into the forest.
//
// projectNode assigned `Parents: node.Parents` — the LIVE map — and entryView.Metadata,
// eventView.Metadata and userView.Permissions were the live map and the live slice too. GET /forest
// builds its view under the read hold and ENCODES IT AFTER RELEASING IT, so every one of those is
// walked by json while another request is free to be writing into it.
func TestForestProjectionCopiesTheMapsItExposes(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "work/aliased")

	node, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the fixture node: %v", err)
	}
	node.Entries = append(node.Entries, core.Entry{
		Content:  "an entry with metadata",
		Metadata: map[string]interface{}{"tag": "original"},
	})
	node.Events["aliased-event"] = core.Event{
		Metadata: map[string]interface{}{"tag": "original"},
		Entries:  []core.Entry{{Content: "an event entry", Metadata: map[string]interface{}{"tag": "original"}}},
	}

	view, found := findNodeView(newNodeView(server.forest, userID), node.ID)
	if !found {
		t.Fatalf("The projection did not contain the fixture node")
	}

	// The fixture has to hold a permission the mutation below actually changes, or the last
	// assertion passes over a value that was never different.
	granted := view.Users[0].Permissions[0]
	if granted != core.AdminPermission {
		t.Fatalf("The fixture user holds %v, not admin, so the permission assertion proves nothing", granted)
	}

	// Everything a concurrent writer would touch, touched.
	node.Parents["intruder"] = "intruder"
	node.Entries[len(node.Entries)-1].Metadata["tag"] = "changed"
	node.Events["aliased-event"].Metadata["tag"] = "changed"
	node.Events["aliased-event"].Entries[0].Metadata["tag"] = "changed"
	node.Users[0].Permissions[0] = core.ReadPermission

	if _, aliased := view.Parents["intruder"]; aliased {
		t.Error("nodeView.Parents is the forest's own map")
	}
	if view.Entries[len(view.Entries)-1].Metadata["tag"] != "original" {
		t.Error("entryView.Metadata is the forest's own map")
	}
	if view.Events["aliased-event"].Metadata["tag"] != "original" {
		t.Error("eventView.Metadata is the forest's own map")
	}
	if view.Events["aliased-event"].Entries[0].Metadata["tag"] != "original" {
		t.Error("the metadata of an event's entry is the forest's own map")
	}
	if view.Users[0].Permissions[0] != granted {
		t.Error("userView.Permissions is the forest's own slice")
	}
}

// nullResponseWriter accepts a response and keeps none of it, so a reader can be run in a tight
// loop without the recorder's buffer being what the test measures.
type nullResponseWriter struct {
	header http.Header
}

func (w *nullResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *nullResponseWriter) Write(payload []byte) (int, error) { return len(payload), nil }

func (w *nullResponseWriter) WriteHeader(int) {}

// The listing routes do not race a writer. Run this under -race.
//
// GET /forest and GET /forest/tree build their view under the read hold and encode it AFTER
// releasing it. That is only safe if the view is a COPY of everything it exposes, and it was not:
// POST /nodes/link writes Parents at runtime, and it is the route that made this class reachable.
func TestListingRoutesDoNotRaceALinkWriter(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	const hub = "org/hub"
	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": hub, "type": "branch",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create the second parent: got %d, want %d", code, http.StatusOK)
	}

	const links = 24
	children := make([]string, 0, links)
	for index := 0; index < links; index++ {
		children = append(children, leafFor(t, server, userID, fmt.Sprintf("work/item-%d", index)))
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for reader := 0; reader < 4; reader++ {
		target := "/forest"
		handler := server.handleGetForest
		if reader%2 == 1 {
			target, handler = "/forest/tree?path=work", server.handleGetTree
		}

		readers.Add(1)
		go func(target string, handler http.HandlerFunc) {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				handler(&nullResponseWriter{}, withUser(httptest.NewRequest("GET", target, nil), userID))
			}
		}(target, handler)
	}

	for _, child := range children {
		if code := post(t, server.handleLinkNode, userID, map[string]interface{}{
			"parent_path": hub, "child_path": child,
		}).Code; code != http.StatusOK {
			t.Errorf("Link %s under %s: got %d, want %d", child, hub, code, http.StatusOK)
		}
		time.Sleep(time.Millisecond)
	}

	close(stop)
	readers.Wait()
}

// A node reachable by several paths is emitted ONCE, and named by id everywhere else.
//
// The projection used to carry an ON-PATH set: cycles terminated, but a doubly-reachable node was
// re-projected on every path through it. A ladder of diamonds is therefore exponential — twelve
// rungs is 37 real nodes and 4096 paths to the last of them, which is megabytes of JSON built UNDER
// THE FOREST READ LOCK, with every writer stalled behind it. Any authenticated caller can build the
// ladder with POST /nodes/link.
func TestForestProjectionEmitsADiamondOnceNotOncePerPath(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	const rungs = 12
	branch := func(path string) {
		t.Helper()
		if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
			"path": path, "type": "branch",
		}).Code; code != http.StatusOK {
			t.Fatalf("Create branch %s: got %d, want %d", path, code, http.StatusOK)
		}
	}

	path := "work"
	branch(path)
	for rung := 1; rung <= rungs; rung++ {
		left := fmt.Sprintf("%s/left-%d", path, rung)
		right := fmt.Sprintf("%s/right-%d", path, rung)
		bottom := fmt.Sprintf("%s/rung-%d", left, rung)
		branch(left)
		branch(right)
		branch(bottom)

		if code := post(t, server.handleLinkNode, userID, map[string]interface{}{
			"parent_path": right, "child_path": bottom,
		}).Code; code != http.StatusOK {
			t.Fatalf("Link rung %d: got %d, want %d", rung, code, http.StatusOK)
		}
		path = bottom
	}

	deepest, err := server.getNodeFromPath(path)
	if err != nil {
		t.Fatalf("Failed to find the bottom of the ladder: %v", err)
	}

	recorder := get(t, server.handleGetForest, userID, "/forest")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /forest: got %d, want %d", recorder.Code, http.StatusOK)
	}

	body := recorder.Body.String()
	// 37 nodes and 48 edges. A document that emits each node once and names the repeats by id is
	// bounded by the number of EDGES, which cannot be anywhere near this.
	if len(body) > 128*1024 {
		t.Errorf("GET /forest over %d diamonds answered %d bytes", rungs, len(body))
	}
	// The bottom of the ladder has two parents, so it is reached twice: once carrying its body and
	// once naming it. 4096 is what one occurrence per PATH looks like.
	if reached := strings.Count(body, `"`+deepest.ID+`"`); reached > 8 {
		t.Errorf("The bottom of the ladder appears %d times in GET /forest, want at most 8", reached)
	}
}
