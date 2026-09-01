package internal

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// GET /stream.
//
// The properties that make a stream usable rather than decorative: it emits promptly, it emits only
// what actually happened, and a client that drops off can come back without losing anything.

// streamReader is a live connection to /stream, together with the way to close it.
type streamReader struct {
	lines  chan string
	cancel context.CancelFunc
	done   chan struct{}
}

// openStream connects to /stream and reads it in the background.
//
// A real server on a real port, because the handler streams: httptest.ResponseRecorder buffers the
// whole response and would only be readable after the request finished, which for this route is
// never.
func openStream(t *testing.T, base, userID, lastEventID string) *streamReader {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	target := base + "/stream"
	request, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		cancel()
		t.Fatalf("Failed to build the stream request: %v", err)
	}
	request.Header.Set("X-Test-User", userID)
	if lastEventID != "" {
		request.Header.Set("Last-Event-ID", lastEventID)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		cancel()
		t.Fatalf("Failed to connect to the stream: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("GET /stream: got %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got := response.Header.Get("Content-Type"); got != "text/event-stream" {
		cancel()
		t.Fatalf("GET /stream answered Content-Type %q", got)
	}

	reader := &streamReader{lines: make(chan string, 256), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(reader.done)
		defer response.Body.Close()
		scanner := bufio.NewScanner(response.Body)
		for scanner.Scan() {
			select {
			case reader.lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	return reader
}

// close releases the connection.
func (r *streamReader) close() {
	r.cancel()
	<-r.done
}

// nextEvent reads the next mutation off the stream, ignoring comments and blank lines.
func (r *streamReader) nextEvent(t *testing.T, within time.Duration) mutationEvent {
	t.Helper()

	deadline := time.After(within)
	for {
		select {
		case line := <-r.lines:
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var event mutationEvent
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
				t.Fatalf("A stream event was not JSON: %v: %s", err, line)
			}
			return event
		case <-deadline:
			t.Fatalf("No event on the stream within %s", within)
		}
	}
}

// silentFor fails if anything arrives on the stream in the given window.
func (r *streamReader) silentFor(t *testing.T, window time.Duration) {
	t.Helper()

	deadline := time.After(window)
	for {
		select {
		case line := <-r.lines:
			if strings.HasPrefix(line, "data: ") {
				t.Fatalf("The stream announced something that did not happen: %s", line)
			}
		case <-deadline:
			return
		}
	}
}

// streamingServer starts a real HTTP server whose routes read the caller from a test header.
func streamingServer(t *testing.T) (*Server, string, string) {
	t.Helper()

	server, _ := newStockServer(t)
	userID := adminID(t, server)

	// The caller comes from a header rather than a token, so the test does not have to mint one.
	// It is the SAME context key authMiddleware writes, so the handlers under test are unchanged.
	withCaller := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			next(w, r.WithContext(context.WithValue(r.Context(), "user_id", r.Header.Get("X-Test-User"))))
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", withCaller(server.handleStream))
	listener := httptest.NewServer(mux)
	t.Cleanup(listener.Close)

	return server, userID, listener.URL
}

// A mutation reaches a connected client within 100ms.
func TestStreamEmitsWithin100msOfAMutation(t *testing.T) {
	server, userID, base := streamingServer(t)
	path := leafFor(t, server, userID, "live/site")

	reader := openStream(t, base, userID, "")
	defer reader.close()

	// The connection is established before the mutation, so the measurement is of the emit and not
	// of the subscribe.
	waitForSubscriber(t, server)

	started := time.Now()
	if code := post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": path, "event_id": "live-1",
	}).Code; code != http.StatusOK {
		t.Fatalf("Start event: got %d", code)
	}

	event := reader.nextEvent(t, 100*time.Millisecond)
	elapsed := time.Since(started)

	if elapsed > 100*time.Millisecond {
		t.Errorf("The stream took %s to emit, want under 100ms", elapsed)
	}
	if event.Type != mutationEventStarted {
		t.Errorf("type: got %q, want %q", event.Type, mutationEventStarted)
	}
	if event.NodePath != path || event.EventID != "live-1" {
		t.Errorf("The event named %s/%s, want %s/live-1", event.NodePath, event.EventID, path)
	}
	if event.EntryIndex != -1 {
		t.Errorf("entry_index: got %d, want -1 for a mutation that is not about an entry", event.EntryIndex)
	}
	if event.Timestamp.IsZero() {
		t.Error("The event carried no timestamp")
	}
}

// An APPEND names the entry it added, and 0 is a real index.
func TestStreamNamesTheEntryThatWasAdded(t *testing.T) {
	server, userID, base := streamingServer(t)
	path := leafFor(t, server, userID, "live/entries")
	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "run"})

	reader := openStream(t, base, userID, "")
	defer reader.close()
	waitForSubscriber(t, server)

	for index := 0; index < 3; index++ {
		post(t, server.handleAppendToEvent, userID, map[string]interface{}{
			"path": path, "event_id": "run", "content": fmt.Sprintf("entry-%d", index),
		})
	}

	for index := 0; index < 3; index++ {
		event := reader.nextEvent(t, time.Second)
		if event.Type != mutationEntryAdded {
			t.Fatalf("type: got %q, want %q", event.Type, mutationEntryAdded)
		}
		if event.EntryIndex != index {
			t.Errorf("entry_index: got %d, want %d", event.EntryIndex, index)
		}
	}
}

// A mutation that FAILED is not announced.
//
// The stream is published to after the persist has been acknowledged. Announcing an attempt would
// be the same lie as a 200 for it, told to every connected client at once.
func TestStreamDoesNotAnnounceWhatDidNotHappen(t *testing.T) {
	server, userID, base := streamingServer(t)
	leafFor(t, server, userID, "live/refused")

	reader := openStream(t, base, userID, "")
	defer reader.close()
	waitForSubscriber(t, server)

	// An append to an event that was never started.
	if code := post(t, server.handleAppendToEvent, userID, map[string]interface{}{
		"path": "live/refused", "event_id": "never-started", "content": "x",
	}).Code; code == http.StatusOK {
		t.Fatal("The fixture succeeded; it is supposed to fail")
	}
	// A start on a node that does not exist.
	post(t, server.handleStartEvent, userID, map[string]interface{}{
		"path": "live/absent", "event_id": "nowhere",
	})

	reader.silentFor(t, 200*time.Millisecond)
}

// A client that drops off and comes back is caught up on what it missed.
//
// This is the property that makes a stream usable. Without it a reconnect silently resumes from
// "now", and every mutation in the gap is lost with nothing to say so.
func TestStreamSurvivesAReconnect(t *testing.T) {
	server, userID, base := streamingServer(t)
	path := leafFor(t, server, userID, "live/reconnect")

	first := openStream(t, base, userID, "")
	waitForSubscriber(t, server)

	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "before"})
	seen := first.nextEvent(t, time.Second)
	if seen.EventID != "before" {
		t.Fatalf("The first event was %s, want before", seen.EventID)
	}

	// The client goes away, and things happen while it is gone.
	first.close()
	for index := 0; index < 3; index++ {
		post(t, server.handleAppendToEvent, userID, map[string]interface{}{
			"path": path, "event_id": "before", "content": fmt.Sprintf("missed-%d", index),
		})
	}
	post(t, server.handleEndEvent, userID, map[string]interface{}{"path": path, "event_id": "before"})

	// It comes back from where it was, the way a browser's EventSource does by itself.
	resumed := openStream(t, base, userID, fmt.Sprintf("%d", seen.Sequence))
	defer resumed.close()

	replayed := []mutationEvent{}
	for len(replayed) < 4 {
		replayed = append(replayed, resumed.nextEvent(t, time.Second))
	}

	for index, event := range replayed {
		if want := seen.Sequence + uint64(index) + 1; event.Sequence != want {
			t.Errorf("Replayed sequence %d, want %d", event.Sequence, want)
		}
	}
	for index := 0; index < 3; index++ {
		if replayed[index].Type != mutationEntryAdded || replayed[index].EntryIndex != index {
			t.Errorf("Replayed %+v, want entry %d", replayed[index], index)
		}
	}
	if replayed[3].Type != mutationEventEnded {
		t.Errorf("Replayed %q last, want %q", replayed[3].Type, mutationEventEnded)
	}

	// And the resumed connection is live, not just a replay.
	post(t, server.handleStartEvent, userID, map[string]interface{}{"path": path, "event_id": "after"})
	if live := resumed.nextEvent(t, time.Second); live.EventID != "after" {
		t.Errorf("The resumed stream went dead: got %+v", live)
	}
}

// A reconnect too old to be caught up is TOLD so, rather than silently resumed from now.
func TestStreamSaysWhenItCannotCatchAClientUp(t *testing.T) {
	server, userID, base := streamingServer(t)
	path := leafFor(t, server, userID, "live/overrun")

	// More mutations than the buffer holds, so sequence 1 has been forgotten.
	for index := 0; index < replayBufferSize+10; index++ {
		server.publish(mutation(mutationNodeCreated, path))
	}

	stale := openStream(t, base, userID, "1")
	defer stale.close()

	if !readsComment(t, stale, "caught_up=false", time.Second) {
		t.Error("A client resuming from before the buffer was not told it had missed events")
	}

	fresh := openStream(t, base, userID, "")
	defer fresh.close()
	if !readsComment(t, fresh, "caught_up=true", time.Second) {
		t.Error("A client that never claimed a position was told it had missed events")
	}
}

// A slow client is dropped from a send rather than blocking the server.
//
// The publisher is a request that has already been acknowledged. One client that stopped reading
// its socket must not be able to stop every write in the process.
func TestASlowClientDoesNotStallThePublisher(t *testing.T) {
	stream := newMutationStream()
	client := stream.subscribe(0, false)
	defer stream.unsubscribe(client)

	// Nothing reads client.events. Publishing far more than its buffer must still return.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for index := 0; index < subscriberBuffer*10; index++ {
			stream.publish(mutation(mutationNodeCreated, "somewhere"))
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("The publisher blocked on a client that was not reading")
	}
}

// waitForSubscriber blocks until the stream handler has registered the connection, so a test is
// timing the emit rather than the connect.
func waitForSubscriber(t *testing.T, server *Server) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		server.mutations.mutex.Lock()
		connected := len(server.mutations.subscribers)
		server.mutations.mutex.Unlock()
		if connected > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("The stream never registered the connection")
}

// readsComment reports whether a comment containing the text arrives in time.
func readsComment(t *testing.T, reader *streamReader, text string, within time.Duration) bool {
	t.Helper()

	deadline := time.After(within)
	for {
		select {
		case line := <-reader.lines:
			if strings.HasPrefix(line, ":") && strings.Contains(line, text) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}
