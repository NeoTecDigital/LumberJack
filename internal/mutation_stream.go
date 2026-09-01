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
)

// mutationEvent is what /stream emits.
//
// EntryIndex is -1 when the mutation is not about an entry, rather than 0: zero is a real index, and
// a client cannot tell a real first entry from an absent one.
type mutationEvent struct {
	Sequence   uint64    `json:"sequence"`
	Type       string    `json:"type"`
	NodePath   string    `json:"node_path"`
	EventID    string    `json:"event_id,omitempty"`
	EntryIndex int       `json:"entry_index"`
	Timestamp  time.Time `json:"timestamp"`
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

	// A client resuming from a sequence older than anything still held cannot be caught up. It is
	// told so, because a client that believes it missed nothing will not go and refetch.
	if len(stream.recent) > 0 && stream.recent[0].Sequence > after+1 {
		client.caughtUp = false
		return client
	}

	for _, past := range stream.recent {
		if past.Sequence > after {
			client.replay = append(client.replay, past)
		}
	}
	return client
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

// publish announces a mutation on the server's stream.
//
// Called AFTER the change has been persisted and acknowledged, never before: an announcement of
// something that has not been written is the same lie as a 200 for it.
func (server *Server) publish(event mutationEvent) {
	if server.mutations == nil {
		return
	}
	// The path is CANONICALISED here, once, rather than at each of the eleven call sites: a feed
	// that names a node differently depending on which route changed it cannot be joined against
	// anything the query surface returned. See node_path.go.
	event.NodePath = server.canonicalPath(event.NodePath)
	server.mutations.publish(event)
}

// mutation builds an event to publish. EntryIndex defaults to -1, which is what "not about an
// entry" has to look like when 0 is a real index.
func mutation(kind, nodePath string) mutationEvent {
	return mutationEvent{Type: kind, NodePath: nodePath, EntryIndex: -1}
}
