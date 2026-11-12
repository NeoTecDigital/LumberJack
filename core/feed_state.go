// Written by Richard Christopher, Copyright 2026 Mindfull
package core

import "encoding/json"

// Feed is internal forest state, not a second authority or capped inbox.
// Immutable attempts/occurrences and mutable presentation marks are separate.
type FeedState struct {
	Preferences map[string]FeedPreferences     `json:"preferences,omitempty"`
	Attempts    map[string][]FeedAttempt       `json:"attempts"`
	Marks       map[string]map[string]FeedMark `json:"marks"`
	Receipts    map[string]FeedReceipt         `json:"receipts"`
	Reminders   map[string]ReminderOccurrence  `json:"reminders"`
}
type FeedAttempt struct {
	Severity  string `json:"severity,omitempty"`
	ID        string `json:"id"`
	CommandID string `json:"command_id"`
	Digest    string `json:"digest"`
	NodeID    string `json:"node_id,omitempty"`
	Path      string `json:"path,omitempty"`
	Operation string `json:"operation"`
	Outcome   string `json:"outcome"`
	Status    int    `json:"status"`
	At        string `json:"at"`
}
type FeedMark struct {
	ReadAt     string `json:"read_at,omitempty"`
	ArchivedAt string `json:"archived_at,omitempty"`
}
type FeedReceipt struct {
	Digest string          `json:"digest"`
	Status int             `json:"status"`
	Result json.RawMessage `json:"result,omitempty"`
}
type ReminderOccurrence struct {
	ID          string   `json:"id"`
	NodeID      string   `json:"node_id"`
	Path        string   `json:"path"`
	EventID     string   `json:"event_id"`
	Start       string   `json:"start"`
	Revision    string   `json:"revision"`
	DeliveredAt string   `json:"delivered_at"`
	Recipients  []string `json:"recipients"`
}
