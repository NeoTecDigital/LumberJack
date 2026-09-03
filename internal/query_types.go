package internal

import (
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// The query surface's request shapes, and the ONE record the predicate evaluator sees.
//
// Every route before this one either returned the whole forest or returned one thing by id. There
// was no filtering, no range, no sort, no page and no way to discover an event at all — POST /events
// needed an event_id the caller had to already possess. This is the layer that answers questions.

// The things a query can select.
const (
	selectNodes   = "nodes"
	selectEvents  = "events"
	selectEntries = "entries"
	selectTime    = "time"
)

// queryRequest is POST /query.
type queryRequest struct {
	Select string       `json:"select"`
	Scope  string       `json:"scope"`
	Depth  *int         `json:"depth"`
	Where  *whereClause `json:"where"`
	Sort   []sortField  `json:"sort"`
	Page   *pageRequest `json:"page"`
}

// whereClause is the predicate grammar, shared verbatim by /query and /aggregate. One grammar and
// one evaluator: a filter that means something different depending on which route parsed it is a
// filter nobody can trust.
type whereClause struct {
	Status   []string          `json:"status"`
	Category []string          `json:"category"`
	UserID   []string          `json:"user_id"`
	Time     *timeClause       `json:"time"`
	Metadata map[string]string `json:"metadata"`
	Text     string            `json:"text"`
}

// timeClause is a half-open range [from, to) over one named time field.
type timeClause struct {
	Field string `json:"field"`
	From  string `json:"from"`
	To    string `json:"to"`
}

// sortField is one level of the ordering.
type sortField struct {
	Field string `json:"field"`
	Dir   string `json:"dir"`
}

// pageRequest is a limit and an opaque position. There is no offset: an offset shifts under every
// concurrent insert, so page two silently repeats or skips whatever arrived while page one was read.
type pageRequest struct {
	Limit  int    `json:"limit"`
	Cursor string `json:"cursor"`
}

// queryResponse is what POST /query answers.
type queryResponse struct {
	Results    []interface{} `json:"results"`
	NextCursor string        `json:"next_cursor,omitempty"`
	Total      int           `json:"total"`
}

// candidate is the ONE shape the predicate evaluator, the sort and the aggregator see.
//
// A node, an event, an entry and a time span are different things, and writing the predicate three
// times is how three subtly different meanings of "status" get shipped. They are flattened to this
// once, at the point they are gathered, and everything downstream reads only this.
type candidate struct {
	Kind      string
	NodePath  string
	NodeID    string
	ID        string
	Index     int
	Status    string
	Category  string
	UserID    string
	Text      []string
	Times     map[string]time.Time
	Metadata  map[string]interface{}
	Timestamp time.Time

	// Duration is only meaningful for a finished event or a closed time span. An ongoing event
	// counts, but it has no duration to sum: adding "now minus start" to a total would make the
	// same query answer differently every time it is asked.
	Duration    time.Duration
	HasDuration bool

	// View is the projected result. It is built while the forest is held for reading and never
	// refers back into it.
	View interface{}
}

// The time fields a candidate can carry, which are also the fields `where.time` and `sort` may name.
const (
	timeFieldStart      = "start_time"
	timeFieldEnd        = "end_time"
	timeFieldTimestamp  = "timestamp"
	timeFieldCreatedAt  = "created_at"
	timeFieldModifiedAt = "modified_at"
)

// timeOf reads a named time off a candidate. The zero time means the candidate does not carry it,
// which is distinct from carrying an epoch.
func (c candidate) timeOf(field string) time.Time {
	if c.Times == nil {
		return time.Time{}
	}
	return c.Times[field]
}

// inEvent reports whether the candidate IS an event or was recorded inside one, which is what
// decides whether status, category and event_id are fields it carries at all.
//
// An entry recorded on the node itself — which is what time tracking and the activity log write —
// is in no event, so its status is ABSENT rather than empty. A node and a time span are never in an
// event; /aggregate refuses to group either by those dimensions before it reaches this, and this
// answers the same way regardless, so the two cannot drift into disagreeing.
func (c candidate) inEvent() bool {
	switch c.Kind {
	case selectEvents:
		return true
	case selectEntries:
		return c.ID != ""
	default:
		return false
	}
}

// nodeSummaryView is a node as a QUERY result: itself, not the subtree under it.
//
// newNodeView projects a node and everything beneath it, which is the right answer for "give me the
// forest" and the wrong one for a page of a hundred nodes — the second node in the page would carry
// the first one's children again.
type nodeSummaryView struct {
	ID            string                 `json:"id"`
	Path          string                 `json:"path"`
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	ParentIDs     []string               `json:"parent_ids"`
	ChildCount    int                    `json:"child_count"`
	EventCount    int                    `json:"event_count"`
	EntryCount    int                    `json:"entry_count"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	AttachmentIDs []string               `json:"attachment_ids,omitempty"`
	CreatedBy     string                 `json:"created_by,omitempty"`
	CreatedAt     time.Time              `json:"created_at,omitempty"`
	ModifiedBy    string                 `json:"modified_by,omitempty"`
	ModifiedAt    time.Time              `json:"modified_at,omitempty"`
}

// eventResultView is an event as a query result: where it lives, what it is, and how much of it
// there is — but not its entries.
//
// Entries are selectable in their own right. Embedding them here makes the size of a page of events
// unbounded in a dimension the caller did not ask about.
type eventResultView struct {
	NodePath   string                 `json:"node_path"`
	EventID    string                 `json:"event_id"`
	Status     core.EventStatus       `json:"status"`
	Category   string                 `json:"category,omitempty"`
	Frequency  string                 `json:"frequency,omitempty"`
	Pattern    string                 `json:"pattern,omitempty"`
	StartTime  *time.Time             `json:"start_time,omitempty"`
	EndTime    *time.Time             `json:"end_time,omitempty"`
	DurationMS *int64                 `json:"duration_ms,omitempty"`
	EntryCount int                    `json:"entry_count"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	CreatedBy  string                 `json:"created_by,omitempty"`
	CreatedAt  time.Time              `json:"created_at,omitempty"`
	ModifiedBy string                 `json:"modified_by,omitempty"`
	ModifiedAt time.Time              `json:"modified_at,omitempty"`
}

// entryResultView is an entry as a query result, addressed by where it is.
//
// EventID is empty for an entry recorded on the node itself rather than inside an event, which is
// what time tracking and the activity log write.
type entryResultView struct {
	// ID is the entry's own identity. EntryIndex is still reported, because it is what an
	// attachment route still addresses an entry by and what a client that pages results reads as a
	// position — but it is a POSITION and not a name: it moves under every insertion and every
	// deletion before it, and only the id survives them.
	ID         string                 `json:"id"`
	NodePath   string                 `json:"node_path"`
	EventID    string                 `json:"event_id,omitempty"`
	EntryIndex int                    `json:"entry_index"`
	Content    interface{}            `json:"content"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	UserID     string                 `json:"user_id"`
	Timestamp  time.Time              `json:"timestamp"`
	// Attachments are PROJECTED. core.Attachment carries the file's bytes.
	Attachments []attachmentView `json:"attachments,omitempty"`
}
