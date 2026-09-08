package internal

import (
	"sync"
	"time"
)

// The mutation stream's plumbing: what a mutation is, and who is listening.
//
// SSE rather than websockets. The feed is UNIDIRECTIONAL — the server says what changed and the
// client says nothing back — so a duplex protocol buys nothing and costs a handshake, a framing
// layer, and a proxy that has to be told about it. An EventSource is four lines of client.

// The kinds of mutation a client is told about.
const (
	mutationNodeCreated  = "node_created"
	mutationNodeLinked   = "node_linked"
	mutationNodeUnlinked = "node_unlinked"
	mutationMetadataSet  = "node_metadata"
	mutationEventPlanned = "event_planned"
	mutationEventStarted = "event_started"
	mutationEventEnded   = "event_ended"
	mutationEntryAdded   = "entry_added"

	// A file appearing on a node or on an entry, and one going away. api_attachments.go published
	// NEITHER: upload and delete were the two mutations the feed never mentioned.
	mutationAttachmentAdded   = "attachment_added"
	mutationAttachmentRemoved = "attachment_removed"

	// THE REMOVALS. There were NO delete kinds at all, because there were almost no delete routes —
	// and a delete that does not publish is worse than one that does not exist: a client that has
	// been told about every other mutation stops polling, so it keeps rendering a node, an event or
	// an entry the engine no longer has. The Seam's generation counter is driven by this feed too,
	// so a silent delete leaves a stale projection cacheable forever.
	mutationNodeDeleted     = "node_deleted"
	mutationEventDeleted    = "event_deleted"
	mutationEventUpdated    = "event_updated"
	mutationEntryDeleted    = "entry_deleted"
	mutationTimeSpanDeleted = "time_span_deleted"
)

// mutationEvent is what /stream emits.
//
// EntryIndex is -1 when the mutation is not about an entry, rather than 0: zero is a real index, and
// a client cannot tell a real first entry from an absent one.
type mutationEvent struct {
	Sequence uint64 `json:"sequence"`
	Type     string `json:"type"`
	NodePath string `json:"node_path"`
	EventID  string `json:"event_id,omitempty"`
	// EntryID names the entry a mutation is about. EntryIndex names where it was; the two are not
	// interchangeable, because an index is invalidated by the very deletions this feed reports and
	// the id is not. Both are carried: the index is what an attachment route still addresses an
	// entry by, and the id is what survives.
	EntryID    string `json:"entry_id,omitempty"`
	EntryIndex int    `json:"entry_index"`
	// PreviousEventID is set only by a rename, and names what the event was called before it. A
	// client holding the old id has no other way to learn that the event it is watching is the one
	// that just appeared under a new name.
	PreviousEventID string    `json:"previous_event_id,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// replayBufferSize is how far back a reconnecting client can be caught up.
//
// A reconnect that cannot be caught up is TOLD so rather than silently resuming from now: a client
// that believes it missed nothing stops refetching, and a gap becomes permanent.
const replayBufferSize = 1024

// subscriberBuffer is how far a single slow client may fall behind before it is dropped.
//
// It is DROPPED rather than blocked. A blocked send from the publisher would hold up the mutation
// that is being acknowledged, so one client that stopped reading its socket would stop every write
// in the process.
const subscriberBuffer = 64

// mutationStream fans mutations out to the connected clients and remembers the recent past.
type mutationStream struct {
	mutex       sync.Mutex
	sequence    uint64
	subscribers map[int]chan mutationEvent
	nextID      int
	recent      []mutationEvent
}

// newMutationStream builds the stream a server publishes to.
func newMutationStream() *mutationStream {
	return &mutationStream{
		subscribers: map[int]chan mutationEvent{},
		recent:      make([]mutationEvent, 0, replayBufferSize),
	}
}

// subscription is one connected client.
type subscription struct {
	id       int
	events   <-chan mutationEvent
	replay   []mutationEvent
	caughtUp bool
}

// subscribe registers a client, optionally from a sequence it has already seen.
//
// Registering and reading the replay happen under ONE hold. Taking the backlog first and then
// subscribing would lose everything published in between, which is exactly the gap a reconnect is
// trying to close.
func (stream *mutationStream) subscribe(after uint64, resuming bool) *subscription {
	stream.mutex.Lock()
	defer stream.mutex.Unlock()

	events := make(chan mutationEvent, subscriberBuffer)
	stream.nextID++
	stream.subscribers[stream.nextID] = events

	client := &subscription{id: stream.nextID, events: events, caughtUp: true}
	if !resuming {
		return client
	}

	client.replay, client.caughtUp = stream.replaySince(after)
	return client
}

// replaySince reports the held mutations after a cursor, and whether the caller can be caught up
// from them at all.
//
// caughtUp is false when the cursor is older than anything still held — a client that believes it
// missed nothing will not go and refetch, so the gap is announced rather than swallowed, and no
// replay is offered because none of it would close the gap. The caller must hold stream.mutex.
func (stream *mutationStream) replaySince(after uint64) (replay []mutationEvent, caughtUp bool) {
	if len(stream.recent) > 0 && stream.recent[0].Sequence > after+1 {
		return nil, false
	}

	for _, past := range stream.recent {
		if past.Sequence > after {
			replay = append(replay, past)
		}
	}
	return replay, true
}

// pollSince is a subscription-free read of the ring: the mutations after a cursor and whether the
// caller is caught up.
//
// It holds NO goroutine between calls, which is the whole difference between a poller and the SSE
// subscribers — a long-lived subscriber is a bounded channel the publisher drops into silently when
// full, an undetectable gap for something that only reads occasionally. The ring is deeper and
// announces its own gap via caughtUp, so a poller re-derives its view rather than missing writes.
func (stream *mutationStream) pollSince(after uint64) ([]mutationEvent, bool) {
	stream.mutex.Lock()
	defer stream.mutex.Unlock()

	return stream.replaySince(after)
}

// unsubscribe releases a client.
func (stream *mutationStream) unsubscribe(client *subscription) {
	stream.mutex.Lock()
	defer stream.mutex.Unlock()

	if events, connected := stream.subscribers[client.id]; connected {
		delete(stream.subscribers, client.id)
		close(events)
	}
}

// publish numbers a mutation, remembers it, and hands it to everyone listening.
//
// A subscriber whose buffer is full is SKIPPED, not waited for. The caller of this is a request
// that has already been acknowledged, and one client that stopped reading must not be able to stop
// the server.
func (stream *mutationStream) publish(event mutationEvent) mutationEvent {
	stream.mutex.Lock()
	defer stream.mutex.Unlock()

	stream.sequence++
	event.Sequence = stream.sequence
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	stream.recent = append(stream.recent, event)
	if len(stream.recent) > replayBufferSize {
		stream.recent = stream.recent[len(stream.recent)-replayBufferSize:]
	}

	for _, events := range stream.subscribers {
		select {
		case events <- event:
		default:
		}
	}
	return event
}

// publish announces a mutation on the server's stream and RETURNS what it announced.
//
// Called AFTER the change has been persisted and acknowledged, never before: an announcement of
// something that has not been written is the same lie as a 200 for it.
//
// The value is returned so an extracted handler body — the one surface HTTP and the embedded API
// share — hands its caller the announced event rather than reconstructing it. A caller receives
// the sequenced, canonical event the feed saw, not a second copy it has to keep in step.
func (server *Server) publish(event mutationEvent) mutationEvent {
	// The path is CANONICALISED here, once, rather than at each of the eleven call sites: a feed
	// that names a node differently depending on which route changed it cannot be joined against
	// anything the query surface returned. See node_path.go. It is canonicalised even on an
	// embedded server with no stream, so the returned event names the node the way every read does.
	event.NodePath = server.canonicalPath(event.NodePath)
	if server.mutations == nil {
		return event
	}
	return server.mutations.publish(event)
}

// pollMutations reads the mutations after a cursor and whether the caller is caught up, for a poller
// that holds no subscription between calls. A server with no stream yet has nothing to report and is
// trivially caught up.
func (server *Server) pollMutations(after uint64) ([]mutationEvent, bool) {
	if server.mutations == nil {
		return nil, true
	}
	return server.mutations.pollSince(after)
}

// PollMutationsBlocking reads the ring after a cursor, waiting up to timeout for something to appear
// if it is empty and returning at once if cancel is closed.
//
// It holds a subscription ONLY while it waits, never between calls — the ring is where the data comes
// from, deeper than a subscriber's channel and able to announce its own gap via caughtUp, and the
// subscription is used only as a doorbell so a wait ends the instant a mutation lands rather than
// after the whole timeout. cancel is the caller's own shutdown signal — the embedded runtime's — so a
// Close returns a blocked poll in milliseconds instead of timeout.
func (server *Server) PollMutationsBlocking(after uint64, timeout time.Duration, cancel <-chan struct{}) ([]mutationEvent, bool) {
	events, caughtUp := server.pollMutations(after)
	if len(events) > 0 || !caughtUp || server.mutations == nil {
		return events, caughtUp
	}

	sub := server.mutations.subscribe(after, false)
	defer server.mutations.unsubscribe(sub)

	// Re-read AFTER subscribing: a mutation published between the first read and the subscription
	// arrives on neither, and would otherwise cost a full timeout to notice.
	if events, caughtUp := server.pollMutations(after); len(events) > 0 || !caughtUp {
		return events, caughtUp
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-sub.events:
	case <-timer.C:
	case <-cancel:
	}
	return server.pollMutations(after)
}

// mutation builds an event to publish. EntryIndex defaults to -1, which is what "not about an
// entry" has to look like when 0 is a real index.
func mutation(kind, nodePath string) mutationEvent {
	return mutationEvent{Type: kind, NodePath: nodePath, EntryIndex: -1}
}
