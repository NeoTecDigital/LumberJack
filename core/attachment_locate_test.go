package core

import (
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"
)

// THE DEFECT: a node keeps attachments in more than one place and the lookup knew about ONE of
// them. An upload to an entry stored the file on Entry.Attachments and answered 200 with an id;
// GET /attachments/{id} resolved that id against Node.Attachments alone and answered 404 for it,
// forever. Two storage locations, one lookup — a write-only route.
//
// These tests are reflective ON PURPOSE. A test that names today's four locations is the same
// defect as a lookup that names today's four locations: it passes on the day someone adds a fifth
// and forgets it. This walks whatever core.Node actually has and insists the resolver reaches
// every place an Attachment can be reached from a node.

// attachmentType and nodeType are the two types the walk below is looking for.
var (
	attachmentType = reflect.TypeOf(Attachment{})
	nodeType       = reflect.TypeOf(Node{})
	timeType       = reflect.TypeOf(time.Time{})
)

// elementType strips the containers off a field type: []Attachment, map[string]Attachment and
// *Attachment all hold the same thing, and where an attachment is stored is not a fact about which
// container it is stored in.
func elementType(typ reflect.Type) reflect.Type {
	for {
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			typ = typ.Elem()
		default:
			return typ
		}
	}
}

// attachmentPaths is every field path from a struct down to a stored Attachment.
//
// The walk does NOT descend through a *Node: a child's attachments belong to the child and are
// reached by naming the child, not by searching its parent. That is also what stops the walk from
// running forever on a DAG.
func attachmentPaths(typ reflect.Type, prefix string) []string {
	var found []string
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.PkgPath != "" {
			continue // unexported: not a place anything is stored on purpose
		}

		element := elementType(field.Type)
		path := prefix + field.Name
		switch {
		case element == attachmentType:
			found = append(found, path)
		case element == nodeType || element == timeType:
			continue
		case element.Kind() == reflect.Struct:
			found = append(found, attachmentPaths(element, path+".")...)
		}
	}
	return found
}

// seededAttachment is bytes distinct per location, so a resolver that finds SOMETHING cannot pass
// by finding the wrong one.
func seededAttachment(id string) Attachment {
	return Attachment{
		ID:         id,
		Name:       id + ".bin",
		Type:       "application/octet-stream",
		Size:       int64(len(id)),
		Hash:       id,
		Data:       []byte(id),
		UploadedBy: "seed-user",
		UploadedAt: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
	}
}

// nodeWithWriter is a leaf the seeding user may change, which is what delete asks for.
func nodeWithWriter(userID string) *Node {
	node := NewNode(LeafNode, "holder")
	node.Users = []User{{ID: userID, Permissions: []Permission{WritePermission}}}
	return node
}

// attachmentSeeds puts one attachment in one named location. The keys are the reflected paths, and
// the test below fails if the two sets differ in either direction — a location the seeds do not
// know about is a location nobody proved the resolver reaches.
func attachmentSeeds() map[string]func(*Node, Attachment) {
	return map[string]func(*Node, Attachment){
		"Attachments": func(node *Node, attachment Attachment) {
			node.Attachments = map[string]Attachment{attachment.ID: attachment}
		},
		"Entries.Attachments": func(node *Node, attachment Attachment) {
			node.Entries = append(node.Entries, Entry{
				Content:     "an entry on the node",
				Attachments: []Attachment{attachment},
			})
		},
		"Events.Entries.Attachments": func(node *Node, attachment Attachment) {
			node.Events["shift"] = Event{Entries: []Entry{
				{Content: "an entry on a live event", Attachments: []Attachment{attachment}},
			}}
		},
		"PlannedEvents.Entries.Attachments": func(node *Node, attachment Attachment) {
			node.PlannedEvents["planned"] = Event{Entries: []Entry{
				{Content: "an entry on a plan", Attachments: []Attachment{attachment}},
			}}
		},
	}
}

// holderFor is the holder name the resolver reports for each reflected storage location. It is a
// second statement of the same table, so a location renamed on one side and not the other fails.
func holderFor(path string) string {
	return map[string]string{
		"Attachments":                       AttachmentOnNode,
		"Entries.Attachments":               AttachmentOnNodeEntry,
		"Events.Entries.Attachments":        AttachmentOnEventEntry,
		"PlannedEvents.Entries.Attachments": AttachmentOnPlannedEntry,
	}[path]
}

// THE CROSS-CHECK: the set of places a node can hold an attachment and the set of places the
// resolver is proven to reach are THE SAME SET. Add a fifth holder to core.Node and this fails
// until the resolver and this table both learn about it.
func TestEveryPlaceANodeHoldsAnAttachmentIsProven(t *testing.T) {
	reflected := attachmentPaths(nodeType, "")
	sort.Strings(reflected)

	if len(reflected) < 4 {
		t.Fatalf("core.Node reflected as %d attachment holders, which cannot be right: %v",
			len(reflected), reflected)
	}

	seeds := attachmentSeeds()
	seeded := make([]string, 0, len(seeds))
	for path := range seeds {
		seeded = append(seeded, path)
	}
	sort.Strings(seeded)

	if !reflect.DeepEqual(reflected, seeded) {
		t.Fatalf("core.Node holds attachments at %v, but only %v are proven resolvable", reflected, seeded)
	}
}

// EVERY holder resolves by id alone, and the bytes that come back are the bytes that went in.
func TestAnAttachmentResolvesFromEveryHolderByIDAlone(t *testing.T) {
	for path, seed := range attachmentSeeds() {
		t.Run(path, func(t *testing.T) {
			node := nodeWithWriter("seed-user")
			want := seededAttachment("id-for-" + path)
			seed(node, want)

			found, where, err := node.FindAttachment(want.ID)
			if err != nil {
				t.Fatalf("An attachment stored at %s did not resolve by id: %v", path, err)
			}
			if where.Holder != holderFor(path) {
				t.Errorf("Resolving %s reported the holder as %q, want %q",
					path, where.Holder, holderFor(path))
			}
			if found.ID != want.ID {
				t.Fatalf("Resolving %s answered %q, want %q", path, found.ID, want.ID)
			}
			if string(found.Data) != string(want.Data) {
				t.Fatalf("Resolving %s answered %q bytes, want %q", path, found.Data, want.Data)
			}
		})
	}
}

// A resolved attachment is a COPY. The route that serves it writes the bytes outside the forest
// hold, so a handle into the stored slice is a handle another request is free to change.
func TestAResolvedAttachmentDoesNotAliasTheStoredOne(t *testing.T) {
	node := nodeWithWriter("seed-user")
	stored := seededAttachment("aliasing")
	node.Attachments = map[string]Attachment{stored.ID: stored}

	found, _, err := node.FindAttachment(stored.ID)
	if err != nil {
		t.Fatalf("Failed to resolve the attachment: %v", err)
	}
	found.Data[0] = 'X'

	if node.Attachments[stored.ID].Data[0] == 'X' {
		t.Fatal("Writing to a resolved attachment changed the stored one: the copy is a handle")
	}
}

// DELETE removes it wherever it lives, so the delete and the lookup agree about what an id names.
func TestDeletingAnAttachmentRemovesItFromEveryHolder(t *testing.T) {
	for path, seed := range attachmentSeeds() {
		t.Run(path, func(t *testing.T) {
			node := nodeWithWriter("seed-user")
			stored := seededAttachment("id-for-" + path)
			seed(node, stored)

			if err := node.DeleteAttachment(stored.ID, "seed-user"); err != nil {
				t.Fatalf("Failed to delete an attachment stored at %s: %v", path, err)
			}
			if _, _, err := node.FindAttachment(stored.ID); err == nil {
				t.Fatalf("An attachment stored at %s still resolves after being deleted", path)
			}
		})
	}
}

// The same bytes in two holders are ONE attachment — the id is the hash of the contents — so
// deleting the id removes both. A delete that left one behind would leave the id resolvable and
// the delete would have reported success for something that did not happen.
func TestDeletingAnAttachmentHeldTwiceRemovesBothCopies(t *testing.T) {
	node := nodeWithWriter("seed-user")
	stored := seededAttachment("held-twice")
	attachmentSeeds()["Attachments"](node, stored)
	attachmentSeeds()["Events.Entries.Attachments"](node, stored)

	if err := node.DeleteAttachment(stored.ID, "seed-user"); err != nil {
		t.Fatalf("Failed to delete: %v", err)
	}
	if _, _, err := node.FindAttachment(stored.ID); err == nil {
		t.Fatal("The attachment still resolves after a delete: one of its two copies survived")
	}
	if len(node.Events["shift"].Entries[0].Attachments) != 0 {
		t.Fatalf("The entry still carries %d attachments after the delete",
			len(node.Events["shift"].Entries[0].Attachments))
	}
}

// An id nobody stored is NOT FOUND, and it says so with the sentinel the route answers 404 for.
func TestDeletingAnAbsentAttachmentReportsNotFound(t *testing.T) {
	node := nodeWithWriter("seed-user")

	err := node.DeleteAttachment("nothing-is-stored-under-this", "seed-user")
	if err == nil {
		t.Fatal("Deleting an attachment that is not there reported success")
	}
	if !errors.Is(err, ErrAttachmentNotFound) {
		t.Fatalf("Deleting an absent attachment answered %v, want the not-found sentinel", err)
	}
}
