package core

import (
	"errors"
	"fmt"
	"sort"
)

// WHERE AN ATTACHMENT LIVES, and the one lookup that knows all of it.
//
// THE DEFECT: a node keeps attachments in FOUR places — its own map, its own entries, the entries
// of each live event, and the entries of each plan — and the download route resolved an id against
// the first of them alone. An upload to an entry answered 200 with an id that GET /attachments/{id}
// then answered 404 for, forever: a write-only route.
//
// An attachment id IS the sha256 of its contents, so an id names bytes and not a place. That is
// what makes resolving it without knowing the holder correct rather than merely convenient: two
// holders carrying the same id carry the same file. A caller therefore needs the NODE and the ID,
// and never has to have kept a note of which entry of which event it hung the file on.
//
// The lookup and the delete walk ONE enumeration — attachmentSlots — so they cannot come to
// disagree about where an attachment can be. A resolver that lists holders and a deleter that lists
// holders separately is the same defect twice, waiting.

// ErrAttachmentNotFound is the sentinel the routes answer 404 for. It is a SENTINEL rather than a
// formatted string because "there is no such file" is not a server failure, and answering 500 for
// it tells a client to retry something that will never succeed.
var ErrAttachmentNotFound = errors.New("attachment not found")

// The holders a node has. Named, because a location is reported and a bare index is not readable.
const (
	AttachmentOnNode         = "node"
	AttachmentOnNodeEntry    = "node_entry"
	AttachmentOnEventEntry   = "event_entry"
	AttachmentOnPlannedEntry = "planned_event_entry"
)

// AttachmentLocation is where on a node one stored attachment is kept.
type AttachmentLocation struct {
	Holder     string
	EventID    string
	EntryIndex int
}

// attachmentSlot is one stored attachment together with the only way to remove it.
type attachmentSlot struct {
	location   AttachmentLocation
	attachment Attachment
	remove     func()
}

// attachmentSlots is EVERY place this node keeps an attachment, in a fixed order.
//
// The order is fixed because two holders may carry the same id — the id is the hash of the bytes,
// so the FILE is the same, but the name it was uploaded under need not be. An answer that depends
// on Go's randomized map iteration would differ between two identical requests.
//
// The caller must hold the node.
func (n *Node) attachmentSlots() []attachmentSlot {
	slots := make([]attachmentSlot, 0, len(n.Attachments))

	for _, id := range sortedAttachmentIDs(n.Attachments) {
		slots = append(slots, attachmentSlot{
			location:   AttachmentLocation{Holder: AttachmentOnNode},
			attachment: n.Attachments[id],
			remove:     func() { delete(n.Attachments, id) },
		})
	}

	slots = append(slots, entryAttachmentSlots(n.Entries,
		AttachmentLocation{Holder: AttachmentOnNodeEntry}, nil)...)
	slots = append(slots, eventAttachmentSlots(n.Events, AttachmentOnEventEntry)...)
	slots = append(slots, eventAttachmentSlots(n.PlannedEvents, AttachmentOnPlannedEntry)...)
	return slots
}

// eventAttachmentSlots is every attachment on the entries of a map of events.
func eventAttachmentSlots(events map[string]Event, holder string) []attachmentSlot {
	var slots []attachmentSlot
	for _, eventID := range sortedEventKeys(events) {
		event := events[eventID]
		// The write-back is what keeps the removal visible: Event is a VALUE in the map, and a
		// value read out of a map is a copy. Its Entries slice happens to share a backing array
		// with the stored one today, which is exactly the kind of aliasing that stops being true
		// quietly. Storing the event back says what is meant.
		writeBack := func() { events[eventID] = event }
		at := AttachmentLocation{Holder: holder, EventID: eventID}
		slots = append(slots, entryAttachmentSlots(event.Entries, at, writeBack)...)
	}
	return slots
}

// entryAttachmentSlots is every attachment on a run of entries.
//
// The removal FILTERS BY ID rather than cutting an index out: one pass may remove several slots,
// and every index behind an index-based removal would be wrong afterwards.
func entryAttachmentSlots(entries []Entry, at AttachmentLocation, writeBack func()) []attachmentSlot {
	var slots []attachmentSlot
	for index := range entries {
		for _, attachment := range entries[index].Attachments {
			id := attachment.ID
			slots = append(slots, attachmentSlot{
				location:   AttachmentLocation{Holder: at.Holder, EventID: at.EventID, EntryIndex: index},
				attachment: attachment,
				remove: func() {
					entries[index].Attachments = withoutAttachment(entries[index].Attachments, id)
					if writeBack != nil {
						writeBack()
					}
				},
			})
		}
	}
	return slots
}

// withoutAttachment is a run of attachments with every copy of one id gone.
//
// A FRESH slice, not a filter in place: the run may share its backing array with a copy of the
// event that holds it, and rewriting that array underneath the copy is a change nobody asked for.
func withoutAttachment(attachments []Attachment, attachmentID string) []Attachment {
	kept := make([]Attachment, 0, len(attachments))
	for _, attachment := range attachments {
		if attachment.ID != attachmentID {
			kept = append(kept, attachment)
		}
	}
	return kept
}

// sortedAttachmentIDs is a node's attachment ids in a fixed order.
func sortedAttachmentIDs(attachments map[string]Attachment) []string {
	ids := make([]string, 0, len(attachments))
	for id := range attachments {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// sortedEventKeys is a map of events' ids in a fixed order.
func sortedEventKeys(events map[string]Event) []string {
	ids := make([]string, 0, len(events))
	for id := range events {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// FindAttachment resolves an id ANYWHERE on this node and says where it found it.
//
// The bytes come back as a COPY. The route that serves them writes them after it has let go of the
// forest, and a handle into the stored slice is a handle another request is free to change.
func (n *Node) FindAttachment(attachmentID string) (*Attachment, AttachmentLocation, error) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for _, slot := range n.attachmentSlots() {
		if slot.attachment.ID != attachmentID {
			continue
		}
		found := slot.attachment
		found.Data = append([]byte(nil), slot.attachment.Data...)
		return &found, slot.location, nil
	}
	return nil, AttachmentLocation{}, fmt.Errorf("%w: %s", ErrAttachmentNotFound, attachmentID)
}

// DeleteAttachment removes an attachment from EVERY holder that carries the id.
//
// It deletes wherever the lookup can see, because a delete that clears fewer places than the
// lookup searches reports success and leaves the id still resolving. The same id in two holders is
// one file — the id is the hash of the contents — so removing all of them is removing the one
// thing the caller named.
func (n *Node) DeleteAttachment(attachmentID string, userID string) error {
	if !n.CheckPermission(userID, WritePermission) {
		return fmt.Errorf("insufficient permissions")
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Every slot is collected BEFORE any of them is removed, so no removal disturbs the walk that
	// is still finding the rest.
	removed := 0
	for _, slot := range n.attachmentSlots() {
		if slot.attachment.ID == attachmentID {
			slot.remove()
			removed++
		}
	}

	if removed == 0 {
		return fmt.Errorf("%w: %s", ErrAttachmentNotFound, attachmentID)
	}
	return nil
}
