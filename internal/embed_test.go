// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The Step 2 gate: the whole event lifecycle driven ENTIRELY through the exported façade — no
// httptest, no router, no LUMBERJACK_JWT_SECRET — asserting the same values the route tests assert
// over HTTP. If this and the HTTP suite agree, the two surfaces are the one implementation the alias
// façade was built to make them.
package internal

import (
	"context"
	"testing"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// embeddedServer is a core-only server with one admin on the root, built without a signing key. The
// admin's permission propagates to every node created beneath the root (AddChildNode copies it), so
// the whole flow runs as one principal.
func embeddedServer(t *testing.T) (*Server, string) {
	t.Helper()
	server := newServerCore(coreConfig())
	t.Cleanup(func() { server.Shutdown(context.Background()) })

	const userID = "admin"
	server.forest.Users = []core.User{{
		ID:          userID,
		Username:    "admin",
		Permissions: []core.Permission{core.AdminPermission},
	}}
	return server, userID
}

func TestEmbeddedLifecycleThroughTheFacade(t *testing.T) {
	server, userID := embeddedServer(t)

	// CreateNode — a leaf to track on, and the branch above it, in one call.
	node, err := server.CreateNode(userID, CreateNodeRequest{Path: "work/site", Type: "leaf"})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if node.Type != "leaf" || node.Name != "site" {
		t.Fatalf("CreateNode = %+v, want a leaf named site", node)
	}
	if node.Path != server.canonicalPath("work/site") {
		t.Errorf("CreateNode path = %q, want %q", node.Path, server.canonicalPath("work/site"))
	}
	if node.ID == "" {
		t.Error("CreateNode returned no id")
	}

	// PlanEvent — a future span.
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	later := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	planned, err := server.PlanEvent(userID, PlanEventRequest{
		Path: "work/site", EventID: "planned-1", StartTime: future, EndTime: later,
	})
	if err != nil {
		t.Fatalf("PlanEvent: %v", err)
	}
	if planned.Type != mutationEventPlanned || planned.EventID != "planned-1" {
		t.Fatalf("PlanEvent announced %+v, want %s for planned-1", planned, mutationEventPlanned)
	}

	// StartEvent — a live event.
	started, err := server.StartEvent(userID, StartEventRequest{Path: "work/site", EventID: "e1"})
	if err != nil {
		t.Fatalf("StartEvent: %v", err)
	}
	if started.Type != mutationEventStarted || started.EventID != "e1" {
		t.Fatalf("StartEvent announced %+v, want %s for e1", started, mutationEventStarted)
	}

	// AppendToEvent — one entry, whose id and index the announcement carries.
	appended, err := server.AppendToEvent(userID, AppendEventRequest{
		Path: "work/site", EventID: "e1", Content: "inspection complete",
	})
	if err != nil {
		t.Fatalf("AppendToEvent: %v", err)
	}
	if appended.Type != mutationEntryAdded || appended.EntryIndex != 0 || appended.EntryID == "" {
		t.Fatalf("AppendToEvent announced %+v, want %s index 0 with an id", appended, mutationEntryAdded)
	}
	if appended.NodePath != server.canonicalPath("work/site") {
		t.Errorf("AppendToEvent node path = %q, want %q", appended.NodePath, server.canonicalPath("work/site"))
	}

	// EndEvent — the same event, ended.
	ended, err := server.EndEvent(userID, EndEventRequest{Path: "work/site", EventID: "e1"})
	if err != nil {
		t.Fatalf("EndEvent: %v", err)
	}
	if ended.Type != mutationEventEnded || ended.EventID != "e1" {
		t.Fatalf("EndEvent announced %+v, want %s for e1", ended, mutationEventEnded)
	}

	// EventEntries — the one entry reads back, content and id intact.
	entries, err := server.EventEntries(userID, EventEntriesRequest{Path: "work/site", EventID: "e1"})
	if err != nil {
		t.Fatalf("EventEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("EventEntries returned %d entries, want 1", len(entries))
	}
	if entries[0].Content != "inspection complete" {
		t.Errorf("entry content = %v, want %q", entries[0].Content, "inspection complete")
	}
	if entries[0].ID != appended.EntryID {
		t.Errorf("entry id = %q, want the id the append announced %q", entries[0].ID, appended.EntryID)
	}

	// Query — the one entry is discoverable.
	q, err := server.Query(userID, QueryRequest{Select: "entries"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if q.Total != 1 || len(q.Results) != 1 {
		t.Fatalf("Query entries: total=%d results=%d, want 1 and 1", q.Total, len(q.Results))
	}

	// Aggregate — one bucket counting the one entry.
	agg, err := server.Aggregate(userID, AggregateRequest{Select: "entries"})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(agg.Buckets) != 1 || agg.Buckets[0].Count != 1 {
		t.Fatalf("Aggregate = %+v, want one bucket of count 1", agg.Buckets)
	}

	// Forest — the tree comes back rooted, with the one branch created under it.
	forest := server.Forest(userID)
	if forest.Name != server.rootName() {
		t.Errorf("Forest root name = %q, want %q", forest.Name, server.rootName())
	}
	if len(forest.Children) != 1 {
		t.Errorf("Forest root has %d children, want 1 (work)", len(forest.Children))
	}

	// StatusOf — the leaf's subtree carries the finished event and its entry.
	site, err := server.StatusOf(userID, "work/site")
	if err != nil {
		t.Fatalf("StatusOf: %v", err)
	}
	if site.Name != "site" {
		t.Errorf("StatusOf name = %q, want site", site.Name)
	}
	event, ok := site.Events["e1"]
	if !ok {
		t.Fatalf("StatusOf: leaf carries no event e1; has %v", site.Events)
	}
	if event.Status != core.EventFinished {
		t.Errorf("event status = %v, want %v", event.Status, core.EventFinished)
	}
	if len(event.Entries) != 1 {
		t.Errorf("event carries %d entries, want 1", len(event.Entries))
	}

	// PollMutations — every announcement the flow made, in order, and the caller is caught up. One
	// node_created (the path is announced once), then plan, start, entry, end.
	events, caughtUp := server.PollMutations(0)
	if !caughtUp {
		t.Error("PollMutations reported a gap over a fresh ring")
	}
	wantTypes := []string{
		mutationNodeCreated, mutationEventPlanned, mutationEventStarted, mutationEntryAdded, mutationEventEnded,
	}
	if len(events) != len(wantTypes) {
		t.Fatalf("PollMutations returned %d events, want %d: %+v", len(events), len(wantTypes), events)
	}
	for i, want := range wantTypes {
		if events[i].Type != want {
			t.Errorf("mutation %d = %q, want %q", i, events[i].Type, want)
		}
	}
}
