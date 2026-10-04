// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// The page bounds for /graph/events.
const (
	DefaultEventLimit = 500
	MaxEventLimit     = 5000
)

// SnapshotOf is the whole graph under forest. The caller holds the forest for reading.
func SnapshotOf(forest *core.Node) (Snapshot, error) {
	state, _, err := load(Root(forest))
	if err != nil {
		return Snapshot{}, err
	}
	return state.snapshot(), nil
}

// ReceiptFor is the stored receipt of a command, if there is one. The caller holds the forest.
func ReceiptFor(forest *core.Node, id string) (Receipt, bool, error) {
	root := Root(forest)
	if root == nil {
		return Receipt{}, false, nil
	}
	bucket := root.Children[bucketID(commandsCollection)]
	if bucket == nil {
		return Receipt{}, false, nil
	}
	node := bucket.Children[nodeID(commandsCollection, id)]
	if node == nil {
		return Receipt{}, false, nil
	}
	return decodeReceipt(node)
}

// Events pages the journal: every command after revision `since`, oldest first, at most limit of
// them. A limit of zero is the default and anything above the maximum is the maximum. The caller
// holds the forest for reading.
func Events(forest *core.Node, since uint64, limit int) (EventsPage, error) {
	page := EventsPage{Events: []Event{}}
	root := Root(forest)
	if root == nil {
		return page, nil
	}
	limit = clampLimit(limit)
	matching := journalAfter(root, since)
	if len(matching) > limit {
		next := matching[limit-1].revision
		page.Next = &next
		matching = matching[:limit]
	}
	for _, item := range matching {
		event, err := decodeEvent(item.entry)
		if err != nil {
			return EventsPage{}, err
		}
		page.Events = append(page.Events, event)
	}
	return page, nil
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return DefaultEventLimit
	}
	if limit > MaxEventLimit {
		return MaxEventLimit
	}
	return limit
}

type journalItem struct {
	revision uint64
	entry    core.Entry
}

// journalAfter is every journal entry past since, in revision order, undecoded.
func journalAfter(root *core.Node, since uint64) []journalItem {
	items := []journalItem{}
	for _, entry := range root.Entries {
		revision, ok := journalRevision(entry)
		if !ok || revision <= since {
			continue
		}
		items = append(items, journalItem{revision: revision, entry: entry})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].revision < items[j].revision })
	return items
}

// journalRevision reads the revision a journal entry carries, and reports false for any other
// entry on the root.
func journalRevision(entry core.Entry) (uint64, bool) {
	if typed, _ := entry.Metadata[typedKey].(string); typed != kindCommand {
		return 0, false
	}
	text, _ := entry.Metadata["revision"].(string)
	revision, err := strconv.ParseUint(text, 10, 64)
	return revision, err == nil
}

func decodeEvent(entry core.Entry) (Event, error) {
	content, _ := entry.Content.(map[string]interface{})
	text, _ := content["event"].(string)
	var event Event
	if err := json.Unmarshal([]byte(text), &event); err != nil {
		return Event{}, fmt.Errorf("journal entry %q: %w", entry.ID, err)
	}
	return event, nil
}
