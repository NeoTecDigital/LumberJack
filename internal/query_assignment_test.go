package internal

import (
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// where.user_id matches an event's ASSIGNEE as well as its creator (phase 18.3).
//
// An event's UserID candidate is its CreatedBy — whoever logged it — and that was the only user a
// where.user_id clause could match. But work is assigned to someone who may not be the one who
// recorded it, so an assignee querying for "my work" found nothing they had not created themselves.
// eventCandidate now carries AssignedTo alongside UserID and the predicate matches EITHER.
//
// OBSERVED RED before the predicate matched AssignedTo
// (go test ./internal/ -run QueryFindsAnEventByItsAssignee):
//
//	--- FAIL: TestQueryFindsAnEventByItsAssignee (0.00s)
//	    query_assignment_test.go:41: where.user_id=user-x did not match an event assigned to user-x (created by user-y)
func TestQueryFindsAnEventByItsAssignee(t *testing.T) {
	node := core.NewNode(core.LeafNode, "work")
	node.Events = map[string]core.Event{"shift": {
		Realizes:   "goal-ship-it",
		AssignedTo: "user-x",
		CreatedBy:  "user-y",
	}}

	candidates := eventCandidates(visit{node: node, path: "forest/work"})
	if len(candidates) != 1 {
		t.Fatalf("flattened %d events, want 1", len(candidates))
	}
	item := candidates[0]

	// The assignee finds work assigned to them though someone else logged it.
	assignee, err := compilePredicate(&whereClause{UserID: []string{"user-x"}})
	if err != nil {
		t.Fatalf("compile the assignee predicate: %v", err)
	}
	if !assignee.match(item) {
		t.Errorf("where.user_id=user-x did not match an event assigned to user-x (created by user-y)")
	}

	// The creator still matches, as they always did.
	creator, err := compilePredicate(&whereClause{UserID: []string{"user-y"}})
	if err != nil {
		t.Fatalf("compile the creator predicate: %v", err)
	}
	if !creator.match(item) {
		t.Errorf("where.user_id=user-y did not match an event created by user-y")
	}

	// A third party is neither the creator nor the assignee and matches neither.
	stranger, err := compilePredicate(&whereClause{UserID: []string{"user-z"}})
	if err != nil {
		t.Fatalf("compile the stranger predicate: %v", err)
	}
	if stranger.match(item) {
		t.Errorf("where.user_id=user-z matched an event neither created by nor assigned to user-z")
	}

	// The result view carries the two new fields the client renders the intent chain from.
	view, ok := item.View.(eventResultView)
	if !ok {
		t.Fatalf("the event candidate's view was %T, want eventResultView", item.View)
	}
	if view.Realizes != "goal-ship-it" {
		t.Errorf("the result view came back realizes %q, want %q", view.Realizes, "goal-ship-it")
	}
	if view.AssignedTo != "user-x" {
		t.Errorf("the result view came back assigned_to %q, want %q", view.AssignedTo, "user-x")
	}
}
