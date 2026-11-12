package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/core"
)

// GET /stream — server-sent events, one per mutation.
//
// The pipes surface is a live feed. Polling the query API is the fallback; this is the correct
// answer. SSE and not websockets: the traffic is one-directional, it survives every proxy that
// understands HTTP, and the client is `new EventSource("/stream")`.
//
// RECONNECT-SAFE, which is the property that makes a stream usable rather than decorative:
//   - every event carries an `id:`, so the browser sends `Last-Event-ID` back automatically;
//   - a reconnect replays everything after that id out of a bounded buffer;
//   - a reconnect too old to replay is TOLD SO, because a client that believes it missed nothing
//     will not refetch, and the gap becomes permanent.

// heartbeatInterval is how often a comment is written down an idle connection.
//
// Not decoration: a proxy that sees nothing on a connection closes it, and so does a phone's
// radio. A comment line is ignored by every SSE client and keeps the path open.
const heartbeatInterval = 20 * time.Second

func (server *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}
	valid := false
	server.readForest(func() { _, err := server.forest.GetUserProfile(userID); valid = err == nil })
	if !valid {
		http.Error(w, "Account unavailable", http.StatusUnauthorized)
		return
	}
	validate := server.streamValidator(r, userID)

	flusher, streamable := w.(http.Flusher)
	if !streamable {
		http.Error(w, "Streaming is not supported by this connection", http.StatusInternalServerError)
		return
	}
	writeStreamHeaders(w)

	after, resuming := resumeFrom(r)
	client, visible := server.subscribeReader(userID, after, resuming)
	defer server.mutations.unsubscribe(client)

	// The client is told whether it was caught up BEFORE anything else, so it knows whether what
	// follows is the whole story or only the part still in the buffer.
	writeComment(w, fmt.Sprintf("connected caught_up=%t epoch=%s", client.caughtUp, server.mutations.epoch))
	flusher.Flush()
	send := server.streamSender(w, userID, visible)

	for _, past := range client.replay {
		if !validate() {
			return
		}
		send(past)
	}
	flusher.Flush()

	pump(r, w, flusher, client, send, validate)
}

// streamValidator answers whether the stream's credential still names its user.
func (server *Server) streamValidator(r *http.Request, userID string) func() bool {
	credential := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return func() bool {
		// Direct library handlers may receive a trusted context; public routes
		// always reach this through authentication with a bearer credential.
		if credential == "" {
			return true
		}
		session, ok := server.applicationSession(credential)
		return ok && session.UserID == userID
	}
}

// subscribeReader registers a reader and reads the paths it may see, under ONE hold of the forest.
//
// The paths are the baseline every later event is judged against: an event about a path the reader
// could see and no longer can owes it a resync. Subscribing first and reading the paths under a later
// hold let a change land in between: delivered to the reader, and already in the baseline, so an
// unlink that revoked a path found it absent and resynchronized nobody. Every change lands under the
// exclusive hold and is published after it, so with both taken under this one hold, a change either
// is in the baseline or lands after it and is delivered — never both.
func (server *Server) subscribeReader(userID string, after uint64, resuming bool) (*subscription, map[string]bool) {
	var client *subscription
	visible := map[string]bool{}
	server.readForest(func() {
		client = server.mutations.subscribe(after, resuming)
		_ = server.walkScope("", nil, func(at visit) {
			if at.node.CheckPermission(userID, core.ReadPermission) {
				visible[at.path] = true
			}
		})
	})
	return client, visible
}

// streamSender writes an event the reader may read, and a resync where a path it could see has gone
// out of its reach.
func (server *Server) streamSender(w http.ResponseWriter, userID string, visible map[string]bool) func(mutationEvent) {
	return func(event mutationEvent) {
		allowed := false
		server.readForest(func() {
			if _, err := server.forest.GetUserProfile(userID); err != nil {
				return
			}
			node, err := server.getNodeFromPath(event.NodePath)
			allowed = err == nil && node.CheckPermission(userID, core.ReadPermission)
		})
		if allowed {
			visible[event.NodePath] = true
			writeEvent(w, event)
		} else if visible[event.NodePath] {
			delete(visible, event.NodePath)
			fmt.Fprint(w, "event: resync\ndata: {}\n\n")
		}
	}
}

// writeStreamHeaders opens a response that is never supposed to end.
func writeStreamHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// A proxy that buffers a response defeats the whole point of one that never finishes.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
}

// pump writes mutations to a client until it goes away.
func pump(r *http.Request, w http.ResponseWriter, flusher http.Flusher, client *subscription, send func(mutationEvent), validate func() bool) {
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case event, open := <-client.events:
			if !open || !validate() {
				return
			}
			send(event)
			flusher.Flush()
		case <-heartbeat.C:
			if !validate() {
				return
			}
			writeComment(w, "keep-alive")
			flusher.Flush()
		case <-r.Context().Done():
			// The client went away. Returning releases the subscription, which is what stops the
			// publisher from filling a buffer nobody will ever read.
			return
		}
	}
}

// resumeFrom reads the position a reconnecting client wants to continue from.
//
// The HEADER is what a browser's EventSource sends by itself; the query parameter is for clients
// that are not a browser. A position that cannot be read is not a resume — starting from "now" is
// the right answer for a client that never said where it was.
func resumeFrom(r *http.Request) (uint64, bool) {
	raw := r.Header.Get("Last-Event-ID")
	if raw == "" {
		raw = r.URL.Query().Get("last_event_id")
	}
	if raw == "" {
		return 0, false
	}

	parsed, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

// writeEvent writes one mutation in the SSE wire format.
//
// The `id:` line is what makes the reconnect work: a browser stores it and sends it back as
// Last-Event-ID on its own, without the client having to remember anything.
func writeEvent(w http.ResponseWriter, event mutationEvent) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.Sequence, event.Type, payload)
}

// writeComment writes an SSE comment, which every client ignores and every proxy counts as traffic.
func writeComment(w http.ResponseWriter, text string) {
	fmt.Fprintf(w, ": %s\n\n", text)
}
