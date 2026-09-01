package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"testing"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// queryOf runs POST /query and decodes the answer.
func queryOf(t *testing.T, server *Server, userID string, body map[string]interface{}) queryResponse {
	t.Helper()

	recorder := post(t, server.handleQuery, userID, body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /query: got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var decoded queryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("POST /query did not answer JSON: %v", err)
	}
	return decoded
}

// pathsOf reads the node_path or path out of a page of results.
func pathsOf(t *testing.T, results []interface{}) []string {
	t.Helper()

	paths := make([]string, 0, len(results))
	for _, result := range results {
		fields, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("A result was not an object: %#v", result)
		}
		if path, present := fields["path"]; present {
			paths = append(paths, fmt.Sprintf("%v", path))
			continue
		}
		paths = append(paths, fmt.Sprintf("%v", fields["node_path"]))
	}
	return paths
}

// A NODE REACHABLE BY TWO PATHS IS COUNTED ONCE.
//
// The forest is a multi-parent DAG. Recursing down Children without a visit set reports the shared
// node — and everything under it — once per path that reaches it, so a count of nodes is wrong by
// however many edges happen to point at the same place.
func TestQueryCountsAMultiParentNodeOnce(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	// forest > shared-fixture > {left, right}, with one leaf under left and a second edge to it
	// from right. The leaf is reachable as shared-fixture/left/twice and shared-fixture/right/twice.
	leafFor(t, server, userID, "shared-fixture/left/twice")
	if code := post(t, server.handleCreateNode, userID, map[string]interface{}{
		"path": "shared-fixture/right", "type": "branch",
	}).Code; code != http.StatusOK {
		t.Fatalf("Create the second parent: got %d", code)
	}

	shared, err := server.getNodeFromPath("shared-fixture/left/twice")
	if err != nil {
		t.Fatalf("Failed to find the shared node: %v", err)
	}
	right, err := server.getNodeFromPath("shared-fixture/right")
	if err != nil {
		t.Fatalf("Failed to find the second parent: %v", err)
	}
	right.Children[shared.ID] = shared
	shared.AddParent(right)

	answer := queryOf(t, server, userID, map[string]interface{}{
		"select": "nodes",
		"scope":  "shared-fixture",
	})

	// scope + left + right + the shared leaf. Four, not five.
	if answer.Total != 4 {
		t.Errorf("Counted %d nodes, want 4: %v", answer.Total, pathsOf(t, answer.Results))
	}

	seen := map[string]int{}
	for _, result := range answer.Results {
		fields := result.(map[string]interface{})
		seen[fmt.Sprintf("%v", fields["id"])]++
	}
	if seen[shared.ID] != 1 {
		t.Errorf("The shared node was reported %d times, want 1", seen[shared.ID])
	}

	// It is reported under the SHALLOWEST path, and under the one the NAME ORDER picks: "left"
	// sorts before "right", so the shared node is reached through left on every request.
	//
	// This is asserted as an exact path rather than as "the same answer twice". Two draws from a
	// randomized order agree about half the time, so a repeat-until-different check passes against
	// a broken implementation often enough to be no check at all.
	if !containsString(pathsOf(t, answer.Results), "shared-fixture/left/twice") {
		t.Errorf("The shared node was not reported under the name-ordered path: %v", pathsOf(t, answer.Results))
	}
}

// Children are walked in NAME ORDER.
//
// Ranging a Go map is deliberately randomized. Without a fixed order the path a shared node is
// reported under, and therefore where a page breaks, differs between two identical requests — and a
// cursor into an order that is not the same twice is a cursor into nothing.
//
// Asserted directly on the walk order over twelve children rather than by running the same query
// twice: the odds of twelve randomly ordered children coming out sorted are one in 479 million,
// where the odds of two draws agreeing over two children are one in two.
func TestChildrenAreWalkedInNameOrder(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	expected := []string{}
	for _, name := range []string{"mike", "alfa", "zulu", "kilo", "echo", "papa", "bravo", "romeo", "delta", "tango", "golf", "sierra"} {
		leafFor(t, server, userID, "ordered/"+name)
		expected = append(expected, "ordered/"+name)
	}
	sort.Strings(expected)

	parent, err := server.getNodeFromPath("ordered")
	if err != nil {
		t.Fatalf("Failed to find the parent: %v", err)
	}

	walked := []string{}
	for _, child := range childrenByName(parent) {
		walked = append(walked, "ordered/"+child.Name)
	}

	if !equalStrings(walked, expected) {
		t.Errorf("Children were walked in\n %v\nwant\n %v", walked, expected)
	}
}

// containsString reports whether a path is among those reported.
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// A cycle terminates. An edge back up the graph is creatable, and a walk that follows it forever
// is a request that never answers.
func TestQueryTerminatesOnACycle(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)

	leafFor(t, server, userID, "cycle/down/deep")
	deep, err := server.getNodeFromPath("cycle/down/deep")
	if err != nil {
		t.Fatalf("Failed to find the deep node: %v", err)
	}
	top, err := server.getNodeFromPath("cycle")
	if err != nil {
		t.Fatalf("Failed to find the top of the cycle: %v", err)
	}

	deep.Type = core.BranchNode
	deep.Children[top.ID] = top
	top.AddParent(deep)

	answer := queryOf(t, server, userID, map[string]interface{}{"select": "nodes", "scope": "cycle"})
	if answer.Total != 3 {
		t.Errorf("Counted %d nodes around a cycle, want 3: %v", answer.Total, pathsOf(t, answer.Results))
	}
}

// depth bounds the walk, and 0 means the scope alone.
func TestQueryDepthBound(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	leafFor(t, server, userID, "deep/one/two/three")

	cases := []struct {
		depth interface{}
		want  int
	}{
		{depth: 0, want: 1},
		{depth: 1, want: 2},
		{depth: 2, want: 3},
		{depth: 3, want: 4},
		{depth: nil, want: 4},
	}

	for _, testCase := range cases {
		request := map[string]interface{}{"select": "nodes", "scope": "deep"}
		if testCase.depth != nil {
			request["depth"] = testCase.depth
		}
		if got := queryOf(t, server, userID, request).Total; got != testCase.want {
			t.Errorf("depth %v: counted %d, want %d", testCase.depth, got, testCase.want)
		}
	}
}

// A caller sees only what CheckPermission(userID, Read) allows — and a permission granted deep in
// the tree is not withdrawn by one that was never granted above it.
func TestQueryIsPermissionFiltered(t *testing.T) {
	server, _ := newStockServer(t)
	adminUserID := adminID(t, server)

	// The reader is added to the root BEFORE these exist, so the whole fixture inherits it.
	readerID := addReadUser(t, server, "reader")
	leafFor(t, server, adminUserID, "acme/visible")
	leafFor(t, server, adminUserID, "acme/hidden")

	hidden, err := server.getNodeFromPath("acme/hidden")
	if err != nil {
		t.Fatalf("Failed to find the node to hide: %v", err)
	}
	// The reader is REMOVED from this one node and nothing else changes, so the admin still sees
	// all three and the assertion below is about permission rather than about a broken query.
	kept := hidden.Users[:0]
	for _, user := range hidden.Users {
		if user.ID != readerID {
			kept = append(kept, user)
		}
	}
	hidden.Users = kept

	answer := queryOf(t, server, readerID, map[string]interface{}{"select": "nodes", "scope": "acme"})
	for _, path := range pathsOf(t, answer.Results) {
		if path == "acme/hidden" {
			t.Fatal("A reader saw a node it has no permission on")
		}
	}
	if answer.Total != 2 {
		t.Errorf("A reader saw %d nodes, want 2 (acme and acme/visible): %v", answer.Total, pathsOf(t, answer.Results))
	}

	// The admin still sees all three, so the assertion above is not passing because the query is
	// broken for everyone.
	if got := queryOf(t, server, adminUserID, map[string]interface{}{"select": "nodes", "scope": "acme"}).Total; got != 3 {
		t.Errorf("The admin saw %d nodes, want 3", got)
	}
}

// A page is stable across a concurrent insert.
//
// With an offset this is the classic failure: page two of an offset-paged feed repeats or skips
// whatever arrived while page one was being read. A keyset cursor names a position in the order, so
// an insert before it does not move it.
func TestCursorPaginationIsStableAcrossAConcurrentInsert(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "paging/events")

	const existing = 30
	for index := 0; index < existing; index++ {
		if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
			"path": path, "event_id": fmt.Sprintf("event-%03d", index),
		}).Code; code != http.StatusOK {
			t.Fatalf("Start event %d: got %d", index, code)
		}
	}

	query := map[string]interface{}{
		"select": "events",
		"scope":  "paging",
		"sort":   []map[string]string{{"field": "created_at", "dir": "asc"}},
		"page":   map[string]interface{}{"limit": 10},
	}

	first := queryOf(t, server, userID, query)
	if len(first.Results) != 10 || first.NextCursor == "" {
		t.Fatalf("First page: %d results, cursor %q", len(first.Results), first.NextCursor)
	}

	// Twenty more events arrive between the pages, concurrently, sorting BEFORE the cursor by id
	// and AFTER it by creation time — which is what the query is ordered by.
	var waiting sync.WaitGroup
	for index := 0; index < 20; index++ {
		waiting.Add(1)
		go func(index int) {
			defer waiting.Done()
			post(t, server.handleStartEvent, userID, map[string]interface{}{
				"path": path, "event_id": fmt.Sprintf("aaa-inserted-%03d", index),
			})
		}(index)
	}
	waiting.Wait()

	// Now page through to the end and assert every original event is seen EXACTLY ONCE.
	seen := map[string]int{}
	for _, result := range first.Results {
		seen[fmt.Sprintf("%v", result.(map[string]interface{})["event_id"])]++
	}

	cursor := first.NextCursor
	for pages := 0; cursor != "" && pages < 20; pages++ {
		query["page"] = map[string]interface{}{"limit": 10, "cursor": cursor}
		next := queryOf(t, server, userID, query)
		for _, result := range next.Results {
			seen[fmt.Sprintf("%v", result.(map[string]interface{})["event_id"])]++
		}
		cursor = next.NextCursor
	}

	for index := 0; index < existing; index++ {
		eventID := fmt.Sprintf("event-%03d", index)
		if seen[eventID] != 1 {
			t.Errorf("%s was seen %d times across the pages, want exactly 1", eventID, seen[eventID])
		}
	}
}

// A cursor is opaque and belongs to the query that produced it.
func TestCursorRefusesWhatItCannotHonour(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "cursor/events")
	for index := 0; index < 5; index++ {
		post(t, server.handleStartEvent, userID, map[string]interface{}{
			"path": path, "event_id": fmt.Sprintf("event-%d", index),
		})
	}

	page := queryOf(t, server, userID, map[string]interface{}{
		"select": "events",
		"sort":   []map[string]string{{"field": "created_at", "dir": "asc"}},
		"page":   map[string]interface{}{"limit": 2},
	})
	if page.NextCursor == "" {
		t.Fatal("The fixture produced no cursor")
	}

	// The SAME cursor under a DIFFERENT sort names a position in an order that no longer exists.
	// Answering with a plausible wrong page is worse than refusing.
	refused := post(t, server.handleQuery, userID, map[string]interface{}{
		"select": "events",
		"sort":   []map[string]string{{"field": "event_id", "dir": "asc"}},
		"page":   map[string]interface{}{"limit": 2, "cursor": page.NextCursor},
	})
	if refused.Code == http.StatusOK {
		t.Error("A cursor was honoured under a sort it was not produced under")
	}

	for _, malformed := range []string{"not-base64!!", "aGVsbG8"} {
		answer := post(t, server.handleQuery, userID, map[string]interface{}{
			"select": "events",
			"page":   map[string]interface{}{"limit": 2, "cursor": malformed},
		})
		if answer.Code != http.StatusBadRequest {
			t.Errorf("Cursor %q: got %d, want %d", malformed, answer.Code, http.StatusBadRequest)
		}
	}
}

// Query results are projected. No password hash, no attachment bytes.
func TestQueryResultsEmitNoSecrets(t *testing.T) {
	server, _ := newStockServer(t)
	userID := adminID(t, server)
	path := leafFor(t, server, userID, "secret/query")

	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "planted-event"})
	plantSecrets(t, server, path)

	for _, selecting := range []string{"nodes", "events", "entries"} {
		body := post(t, server.handleQuery, userID, map[string]interface{}{
			"select": selecting, "page": map[string]interface{}{"limit": 1000},
		}).Body.String()
		assertNoSecrets(t, "POST /query select="+selecting, body)
	}
}

// equalStrings compares two orders of paths.
func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
