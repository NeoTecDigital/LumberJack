package core

import (
	"sync"
	"time"
)

// Permission represents a permission level for users
type Permission int

// LeafType represents the type of a leaf in the tree-forest
type LeafType int

// EventStatus represents the current status of a timed event
type EventStatus string

// Event represents an event with start/end times and entries.
//
// Realizes links the event to the intent or goal it fulfils — the intent→action→event chain. It is
// another object's id, stored and returned OPAQUELY: the engine does not verify the referent exists,
// for the same reason Entry.ParentID is unvalidated (an event may outlive what it realized, and the
// reader can make the check). Empty means the event realizes nothing named.
//
// AssignedTo is the user the event is assigned to, which is distinct from CreatedBy: work is done by
// someone other than whoever logged it. A where.user_id query surfaces an event by EITHER — see
// eventCandidate — so an assignee finds work assigned to them without having created it.
type Event struct {
	StartTime  *time.Time             `json:"start_time,omitempty"`
	EndTime    *time.Time             `json:"end_time,omitempty"`
	Entries    []Entry                `json:"entries"`
	Metadata   map[string]interface{} `json:"metadata"`
	Status     EventStatus            `json:"status"`
	Category   string                 `json:"category,omitempty"`
	Realizes   string                 `json:"realizes,omitempty"`
	AssignedTo string                 `json:"assigned_to,omitempty"`
	Frequency  string                 `json:"frequency,omitempty"`
	Pattern    string                 `json:"pattern,omitempty"`
	CreatedBy  string                 `json:"created_by,omitempty"`
	CreatedAt  time.Time              `json:"created_at,omitempty"`
	ModifiedBy string                 `json:"modified_by,omitempty"`
	ModifiedAt time.Time              `json:"modified_at,omitempty"`
}

// EventSummary provides a summary of the event's timing and status
type EventSummary struct {
	Status         EventStatus `json:"status"`
	Duration       *string     `json:"duration,omitempty"`
	RemainingTime  *string     `json:"remaining_time,omitempty"`
	EntriesCount   int         `json:"entries_count"`
	LastUpdateTime *time.Time  `json:"last_update_time,omitempty"`
}

// NodeType is a node's ADVISORY default-view hint — LeafNode or BranchNode — and NOTHING MORE.
//
// It was once a mutual-exclusion invariant: a leaf carried events and entries and could not hold a
// child, a branch held children and could carry neither, and four guards enforced the split
// (StartEvent, PlanEvent, AddChildNode and promoteToBranch). Phase 18.3 removed that split, because
// the singleton's shape — category{goal{routine{event}}} — is a node that holds children AND events
// at once, and the invariant made it structurally illegal.
//
// So the engine NEVER refuses an operation on the strength of Type. It stores it, returns it, and
// lets a node acquire the branch hint when a child is nested through it (markBranch) because
// "branch" is the accurate default view for something that has children — a hint for how to draw a
// node by default, not a fact about what it may hold. Node.Kind carries the product's own taxonomy
// (category/goal/routine); Type is only leaf-or-branch and only a hint.
type NodeType int

// Entry represents an entry in the node.
//
// ID IS THE ENTRY'S IDENTITY, and until it existed there was none. An entry was addressed by
// (node_path, event_id, entry_index), and an index is invalidated by every insertion and every
// deletion before it — so two clients holding the same address held it for two different entries
// the moment anything was removed, and a delete keyed on an index deletes whatever has slid into
// that position. Reply-to, edit, delete, react, permalink and read-receipt all need a name for one
// entry that survives the entries around it changing.
//
// It is minted at creation and never rewritten. An entry read out of a state file written before
// this field existed carries the empty string, and is given a DERIVED id at load — see
// entry_identity.go, which explains why the derivation has to be deterministic rather than fresh.
// ParentID and Rank make an entry NESTABLE and REORDERABLE as data, which the address (node_path,
// event_id, entry_index) never could: nesting under an index moves when anything above it moves, and
// there was no field to write an order into at all.
//
// ParentID is another entry's ID — a reply/thread parent. It is stored and returned; the engine does
// NOT verify the parent exists (a reply may outlive the message it answered, and validating it here
// would couple two entries' lifecycles for a check the reader can make). Empty means "top level".
//
// Rank is an OPAQUE fractional-index string. The engine stores it, returns it, and orders entries by
// LEXICOGRAPHIC string sort where it orders them — it does not parse it and does not GENERATE one.
// A string so a caller can insert between two ranks ("a", "b" -> "an") without renumbering; the
// between-two arithmetic is the client's (phase 20). An entry created without a rank carries the
// empty string and is simply appended.
type Entry struct {
	ID          string                 `json:"id"`
	ParentID    string                 `json:"parent_id,omitempty"`
	Rank        string                 `json:"rank,omitempty"`
	Content     interface{}            `json:"content"`
	Metadata    map[string]interface{} `json:"metadata"`
	UserID      string                 `json:"user_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Attachments []Attachment           `json:"attachments,omitempty"`
	CreatedBy   string                 `json:"created_by,omitempty"`
	CreatedAt   time.Time              `json:"created_at,omitempty"`
	ModifiedBy  string                 `json:"modified_by,omitempty"`
	ModifiedAt  time.Time              `json:"modified_at,omitempty"`
}

// Node represents a node in the tree-forest.
//
// Kind is the PRODUCT'S taxonomy for the node — a free-form hint the singleton uses (category, goal,
// routine, …) that the engine stores and returns but does not interpret. It is distinct from Type,
// which is only the leaf/branch view hint (see NodeType): Kind is "what this node is to the product",
// Type is "how to draw it by default". Empty means untyped.
type Node struct {
	ID            string                `json:"id"`
	Type          NodeType              `json:"type"`
	Kind          string                `json:"kind,omitempty"`
	Name          string                `json:"name"`
	Parents       map[string]string     `json:"parents"`
	Children      map[string]*Node      `json:"children"`
	Events        map[string]Event      `json:"events"`
	PlannedEvents map[string]Event      `json:"planned_events"`
	Users         []User                `json:"users"`
	Entries       []Entry               `json:"entries"`
	Attachments   map[string]Attachment `json:"attachments,omitempty"`
	// Metadata is the node's own annotations, which is where a canvas layout lives under the
	// reserved CanvasMetadataKey. It is on the NODE rather than in a parallel store so that a node
	// and its placement cannot drift apart: deleting the node deletes the placement, and there is
	// no second thing to keep in step. Absent from a state file written before it existed, which
	// unmarshals as nil and is created on first write.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// Internal command acknowledgments are persisted, never projected by HTTP views.
	CommandReceipts map[string]interface{} `json:"command_receipts,omitempty"`
	// Correspondence is the hub's durable outbox/inbox, stored on the forest.
	// It is internal state and is excluded from user-facing node projections.
	Correspondence      *CorrespondenceState          `json:"correspondence,omitempty"`
	ApplicationSessions map[string]ApplicationSession `json:"application_sessions,omitempty"`
	// MFAChallenges is the forest's pending second-factor store, keyed by challenge id. Like
	// ApplicationSessions it is backend state excluded from every user-facing node projection, and it
	// holds only a keyed hash of each code — never the code — with an attempt count and an expiry, so
	// a state file leak cannot be replayed into a login and a stalled challenge sweeps itself out.
	MFAChallenges map[string]MFAChallenge `json:"mfa_challenges,omitempty"`
	mutex         sync.RWMutex            `json:"-"`
	CreatedBy           string                        `json:"created_by,omitempty"`
	CreatedAt           time.Time                     `json:"created_at,omitempty"`
	ModifiedBy          string                        `json:"modified_by,omitempty"`
	ModifiedAt          time.Time                     `json:"modified_at,omitempty"`
}

// Add to existing types
type Attachment struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"` // mime type
	Size       int64     `json:"size"`
	Hash       string    `json:"hash"` // sha256 hash
	Data       []byte    `json:"data"` // actual file data stored in state file
	UploadedBy string    `json:"uploaded_by"`
	UploadedAt time.Time `json:"uploaded_at"`
}

// User represents a user in the system
//
// MFAEnabled turns the login into a two-step exchange: a verified password mints a short-lived
// challenge instead of a session, and a code delivered out of band to Phone is what completes it.
// It is the ONLY MFA state on the account — the code itself never lives here, only in a hashed,
// TTL-swept challenge store on the forest (see MFAChallenge) — so the profile projection can carry
// this flag without ever carrying a secret. Absent from a state file written before it existed,
// which unmarshals as false: an account is not silently opted into a second factor by an upgrade.
// FailedLogins and LockedUntil are the per-ACCOUNT half of the rate limit, and they live here rather
// than in memory for one reason: a counter a restart clears is a counter an attacker clears. They
// are written by the same changeForest every other account fact is, so a lockout is as durable as
// the password it protects.
//
// FailedLogins counts CONSECUTIVE misses and is reset by any success; LockedUntil is a unix second
// past which the account answers again, and is zero when the account is open. Both are omitempty and
// both unmarshal as zero out of a state file written before they existed, which is the correct
// reading: an account nobody has ever mistyped is open.
type User struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Username     string       `json:"username"`
	Email        string       `json:"email"`
	Password     string       `json:"password"`
	Organization string       `json:"organization"`
	Phone        string       `json:"phone"`
	Permissions  []Permission `json:"permissions"`
	MFAEnabled   bool         `json:"mfa_enabled,omitempty"`
	FailedLogins int          `json:"failed_logins,omitempty"`
	LockedUntil  int64        `json:"locked_until,omitempty"`
}
