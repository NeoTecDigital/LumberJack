package core

import (
	"testing"
	"time"
)

// A NODE HOLDS CHILDREN AND EVENTS/ENTRIES AT ONCE (phase 18.3).
//
// The leaf/branch dichotomy was a mutual-exclusion invariant enforced at four sites: StartEvent and
// PlanEvent refused a non-leaf, AddChildNode refused a leaf, and promoteToBranch refused a leaf that
// already recorded anything. `category{goal{routine{event}}}` — the shape the singleton manipulates
// — was therefore structurally illegal. NodeType is now an advisory default VIEW hint and nothing
// refuses a legal operation on the strength of it.
//
// OBSERVED RED with the four guards in place (go test ./internal/core/ -run HoldsChildrenAndEvents):
//
//	--- FAIL: TestANodeHoldsChildrenAndEventsAtOnce (0.00s)
//	    node_mixed_test.go:29: add a child to a node that records an event: cannot add a child to leaf node holder
func TestANodeHoldsChildrenAndEventsAtOnce(t *testing.T) {
	writer := []User{{ID: "u", Permissions: []Permission{WritePermission}}}

	// A leaf that records an event can still gain a child — the AddChildNode leaf guard is gone.
	holder := NewNode(LeafNode, "holder")
	holder.Users = writer
	if err := holder.StartEvent("e1", "u", nil, nil, map[string]interface{}{}); err != nil {
		t.Fatalf("start an event on a leaf: %v", err)
	}
	if _, err := holder.AddChildNode("child", LeafNode, "u"); err != nil {
		t.Fatalf("add a child to a node that records an event: %v", err)
	}
	if len(holder.Events) != 1 {
		t.Errorf("the event was lost when the child was added: %d events", len(holder.Events))
	}
	if len(holder.Children) != 1 {
		t.Errorf("the child was not added: %d children", len(holder.Children))
	}

	// A node that holds children can start AND plan events — the StartEvent/PlanEvent leaf guards
	// are gone.
	branch := NewNode(BranchNode, "branch")
	branch.Users = writer
	if _, err := branch.AddChildNode("kid", LeafNode, "u"); err != nil {
		t.Fatalf("add a child to a branch: %v", err)
	}
	if err := branch.StartEvent("e2", "u", nil, nil, map[string]interface{}{}); err != nil {
		t.Fatalf("start an event on a node with children: %v", err)
	}
	if len(branch.Events) != 1 {
		t.Errorf("the event was not started on the node with children: %d events", len(branch.Events))
	}
	future := time.Now().Add(time.Hour)
	if err := branch.PlanEvent("p1", "u", &future, nil, map[string]interface{}{}); err != nil {
		t.Fatalf("plan an event on a node with children: %v", err)
	}
	if len(branch.PlannedEvents) != 1 {
		t.Errorf("the event was not planned on the node with children: %d planned", len(branch.PlannedEvents))
	}
	if len(branch.Children) != 1 {
		t.Errorf("the child was lost when the events were added: %d children", len(branch.Children))
	}
}
