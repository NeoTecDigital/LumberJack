package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
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
	if _, ok := userIDFrom(r); !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	flusher, streamable := w.(http.Flusher)
	if !streamable {
		http.Error(w, "Streaming is not supported by this connection", http.StatusInternalServerError)
		return
	}
	writeStreamHeaders(w)

	after, resuming := resumeFrom(r)
	client := server.mutations.subscribe(after, resuming)
	defer server.mutations.unsubscribe(client)

	// The client is told whether it was caught up BEFORE anything else, so it knows whether what
	// follows is the whole story or only the part still in the buffer.
	writeComment(w, fmt.Sprintf("connected caught_up=%t", client.caughtUp))
	flusher.Flush()

	for _, past := range client.replay {
		writeEvent(w, past)
	}
	flusher.Flush()

	pump(r, w, flusher, client)
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
func pump(r *http.Request, w http.ResponseWriter, flusher http.Flusher, client *subscription) {
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case event, open := <-client.events:
			if !open {
				return
			}
			writeEvent(w, event)
			flusher.Flush()
		case <-heartbeat.C:
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
