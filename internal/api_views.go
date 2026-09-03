package internal

import (
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// The shapes an HTTP client is given.
//
// core.User carries the bcrypt hash of the password in a field with a `json:"password"` tag, and a
// core.Node carries its users. So GET /forest, GET /users and GET /forest/tree each handed every
// caller the admin's password hash. These projections are DISTINCT TYPES rather than a copy of the
// live struct with the field blanked: blanking it would mutate the forest the server is still
// serving from, and a projection cannot be forgotten the way a blanking step can.
//
// core.Attachment carries the FILE'S BYTES the same way, in a field tagged `json:"data"`. A node
// view used to embed core.Attachment and core.Entry whole, so every listing of the forest shipped
// every file anyone had ever uploaded, to anyone who could read any part of the tree. An attachment
// is projected to its metadata; its bytes leave by GET /attachments/{id} and nowhere else.
//
// A field is here because a client needs it. The hash is not one of them, and neither are the bytes.

// userView is a user as a client may see one.
type userView struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Username     string            `json:"username"`
	Email        string            `json:"email"`
	Organization string            `json:"organization"`
	Phone        string            `json:"phone"`
	Permissions  []core.Permission `json:"permissions"`
}

// attachmentView is an attachment as a client may see one: everything needed to decide whether to
// fetch it, and nothing of what fetching it would return.
type attachmentView struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Size       int64     `json:"size"`
	Hash       string    `json:"hash"`
	UploadedBy string    `json:"uploaded_by"`
	UploadedAt time.Time `json:"uploaded_at"`
}

// entryView is an entry as a client may see one, attachments projected.
//
// ID is carried because an entry that cannot be named cannot be replied to, edited or deleted: it
// is the whole reason core.Entry has one. Every route that returns an entry returns it.
type entryView struct {
	ID          string                 `json:"id"`
	Content     interface{}            `json:"content"`
	Metadata    map[string]interface{} `json:"metadata"`
	UserID      string                 `json:"user_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Attachments []attachmentView       `json:"attachments,omitempty"`
	CreatedBy   string                 `json:"created_by,omitempty"`
	CreatedAt   time.Time              `json:"created_at,omitempty"`
	ModifiedBy  string                 `json:"modified_by,omitempty"`
	ModifiedAt  time.Time              `json:"modified_at,omitempty"`
}

// eventView is an event as a client may see one, entries projected.
type eventView struct {
	StartTime  *time.Time             `json:"start_time,omitempty"`
	EndTime    *time.Time             `json:"end_time,omitempty"`
	Entries    []entryView            `json:"entries"`
	Metadata   map[string]interface{} `json:"metadata"`
	Status     core.EventStatus       `json:"status"`
	Category   string                 `json:"category,omitempty"`
	Frequency  string                 `json:"frequency,omitempty"`
	Pattern    string                 `json:"pattern,omitempty"`
	CreatedBy  string                 `json:"created_by,omitempty"`
	CreatedAt  time.Time              `json:"created_at,omitempty"`
	ModifiedBy string                 `json:"modified_by,omitempty"`
	ModifiedAt time.Time              `json:"modified_at,omitempty"`
}

// nodeView is a node as a client may see one, users projected and children projected recursively.
//
// Reference marks a node whose BODY is somewhere else in the same document. The forest is a DAG, so
// a node with two parents is reached twice; see forestProjector.
type nodeView struct {
	ID            string                    `json:"id"`
	Type          core.NodeType             `json:"type"`
	Name          string                    `json:"name"`
	Reference     bool                      `json:"ref,omitempty"`
	Parents       map[string]string         `json:"parents"`
	Children      map[string]nodeView       `json:"children"`
	Events        map[string]eventView      `json:"events"`
	PlannedEvents map[string]eventView      `json:"planned_events"`
	Users         []userView                `json:"users"`
	Entries       []entryView               `json:"entries"`
	Attachments   map[string]attachmentView `json:"attachments,omitempty"`
	CreatedBy     string                    `json:"created_by,omitempty"`
	CreatedAt     time.Time                 `json:"created_at,omitempty"`
	ModifiedBy    string                    `json:"modified_by,omitempty"`
	ModifiedAt    time.Time                 `json:"modified_at,omitempty"`
}

// newUserView projects one user.
func newUserView(user core.User) userView {
	return userView{
		ID:           user.ID,
		Name:         user.Name,
		Username:     user.Username,
		Email:        user.Email,
		Organization: user.Organization,
		Phone:        user.Phone,
		Permissions:  append([]core.Permission(nil), user.Permissions...),
	}
}

// newUserViews projects a list of users. An empty list stays an empty list rather than becoming
// JSON null, so a client can iterate the answer without checking it first.
func newUserViews(users []core.User) []userView {
	views := make([]userView, 0, len(users))
	for _, user := range users {
		views = append(views, newUserView(user))
	}
	return views
}

// newAttachmentView projects one attachment. Data is absent by construction.
func newAttachmentView(attachment core.Attachment) attachmentView {
	return attachmentView{
		ID:         attachment.ID,
		Name:       attachment.Name,
		Type:       attachment.Type,
		Size:       attachment.Size,
		Hash:       attachment.Hash,
		UploadedBy: attachment.UploadedBy,
		UploadedAt: attachment.UploadedAt,
	}
}

// newAttachmentViews projects the attachments hanging off a node, keyed as they were.
func newAttachmentViews(attachments map[string]core.Attachment) map[string]attachmentView {
	if len(attachments) == 0 {
		return nil
	}

	views := make(map[string]attachmentView, len(attachments))
	for id, attachment := range attachments {
		views[id] = newAttachmentView(attachment)
	}
	return views
}

// newEntryView projects one entry.
func newEntryView(entry core.Entry) entryView {
	view := entryView{
		ID:         entry.ID,
		Content:    copyValue(entry.Content),
		Metadata:   copyMetadataMap(entry.Metadata),
		UserID:     entry.UserID,
		Timestamp:  entry.Timestamp,
		CreatedBy:  entry.CreatedBy,
		CreatedAt:  entry.CreatedAt,
		ModifiedBy: entry.ModifiedBy,
		ModifiedAt: entry.ModifiedAt,
	}

	for _, attachment := range entry.Attachments {
		view.Attachments = append(view.Attachments, newAttachmentView(attachment))
	}
	return view
}

// newEntryViews projects a list of entries, empty staying empty rather than becoming JSON null.
func newEntryViews(entries []core.Entry) []entryView {
	views := make([]entryView, 0, len(entries))
	for _, entry := range entries {
		views = append(views, newEntryView(entry))
	}
	return views
}

// newEventView projects one event.
func newEventView(event core.Event) eventView {
	return eventView{
		StartTime:  event.StartTime,
		EndTime:    event.EndTime,
		Entries:    newEntryViews(event.Entries),
		Metadata:   copyMetadataMap(event.Metadata),
		Status:     event.Status,
		Category:   event.Category,
		Frequency:  event.Frequency,
		Pattern:    event.Pattern,
		CreatedBy:  event.CreatedBy,
		CreatedAt:  event.CreatedAt,
		ModifiedBy: event.ModifiedBy,
		ModifiedAt: event.ModifiedAt,
	}
}

// newEventViews projects a map of events, keyed as they were.
func newEventViews(events map[string]core.Event) map[string]eventView {
	views := make(map[string]eventView, len(events))
	for id, event := range events {
		views[id] = newEventView(event)
	}
	return views
}
