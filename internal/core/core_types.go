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

// Event represents an event with start/end times and entries
type Event struct {
	StartTime  *time.Time             `json:"start_time,omitempty"`
	EndTime    *time.Time             `json:"end_time,omitempty"`
	Entries    []Entry                `json:"entries"`
	Metadata   map[string]interface{} `json:"metadata"`
	Status     EventStatus            `json:"status"`
	Category   string                 `json:"category,omitempty"`
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

// NodeType represents the type of a node in the tree-forest
type NodeType int

// Entry represents an entry in the node
type Entry struct {
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

// Node represents a node in the tree-forest
type Node struct {
	ID            string                `json:"id"`
	Type          NodeType              `json:"type"`
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
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	mutex      sync.RWMutex           `json:"-"`
	CreatedBy  string                 `json:"created_by,omitempty"`
	CreatedAt  time.Time              `json:"created_at,omitempty"`
	ModifiedBy string                 `json:"modified_by,omitempty"`
	ModifiedAt time.Time              `json:"modified_at,omitempty"`
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
type User struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Username     string       `json:"username"`
	Email        string       `json:"email"`
	Password     string       `json:"password"`
	Organization string       `json:"organization"`
	Phone        string       `json:"phone"`
	Permissions  []Permission `json:"permissions"`
}
