package core

import (
	"fmt"
	"time"
)

// AddActivity adds an activity entry to the node: no parent, no rank, appended in order.
//
// It is the node-level log write (assign_user, time sentinels), and it is AddEntry with the two
// structural fields left empty — one place mints an entry, so a field added to that mint reaches
// every writer without being copied into each.
func (n *Node) AddActivity(content interface{}, metadata map[string]interface{}, userID string) {
	n.AddEntry(content, metadata, userID, "", "")
}

// AddEntry appends an entry to the node's own entries and RETURNS a copy of what it stored, id and
// all — because the caller (POST /entries) must answer the minted id, and reading it back by index
// after the hold is exactly the position-is-not-a-name defect the id exists to end.
//
// parentID and rank are stored opaquely (see the Entry doc): the engine neither validates the parent
// nor generates a rank. An empty rank is stored empty and the entry is appended after the last.
func (n *Node) AddEntry(content interface{}, metadata map[string]interface{}, userID, parentID, rank string) Entry {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	entry := Entry{
		ID:        GenerateEntryID(),
		ParentID:  parentID,
		Rank:      rank,
		Content:   content,
		Metadata:  metadata,
		UserID:    userID,
		Timestamp: time.Now(),
	}
	n.Entries = append(n.Entries, entry)
	return entry
}

// AddChild adds a child node with proper parent linking
func (n *Node) AddChild(child *Node) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	child.AddParent(n)
	n.Children[child.ID] = child
	return nil
}

// AddChildNode creates a child of this node by NAME, which is what a path names.
//
// It is IDEMPOTENT: a child of that name and type is returned rather than duplicated, so a client
// that creates the same path twice gets the same node instead of a second one the path lookup can
// never reach.
//
// The child INHERITS the parent's users, because a node nobody can write to is a node no event can
// be started on, and the permission a user was granted on a tree is the permission they hold over
// what grows on it. Only the identity and the permissions are copied; credentials are not.
func (n *Node) AddChildNode(name string, nodeType NodeType, userID string) (*Node, error) {
	if name == "" {
		return nil, fmt.Errorf("node name cannot be empty")
	}

	if n.Type != BranchNode {
		return nil, fmt.Errorf("cannot add a child to leaf node %s", n.Name)
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	for _, child := range n.Children {
		if child.Name != name {
			continue
		}
		if child.Type != nodeType {
			return nil, fmt.Errorf("node already exists with a different type: %s", name)
		}
		return child, nil
	}

	child := NewNode(nodeType, name)
	child.CreatedBy = userID
	child.CreatedAt = time.Now()
	child.ModifiedBy = userID
	child.ModifiedAt = child.CreatedAt
	child.AddParent(n)
	for _, user := range n.Users {
		child.Users = append(child.Users, User{
			ID:          user.ID,
			Name:        user.Name,
			Username:    user.Username,
			Permissions: append([]Permission(nil), user.Permissions...),
		})
	}

	n.Children[child.ID] = child
	return child, nil
}

// ChildNamed is the child a path segment names, or nil if there is none.
func (n *Node) ChildNamed(name string) *Node {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for _, child := range n.Children {
		if child.Name == name {
			return child
		}
	}
	return nil
}

// AddBranchChild adds the child an INTERMEDIATE segment of a path names.
//
// Such a segment holds a child, which is what a branch is, so an empty leaf already sitting there is
// PROMOTED rather than refused. Refusing it was why POST /nodes could not nest under a path it had
// itself created: the first call made a leaf, and every call below it answered 409 forever.
func (n *Node) AddBranchChild(name string, userID string) (*Node, error) {
	existing := n.ChildNamed(name)
	if existing == nil {
		return n.AddChildNode(name, BranchNode, userID)
	}
	if existing.Type == BranchNode {
		return existing, nil
	}
	if err := existing.promoteToBranch(); err != nil {
		return nil, err
	}
	return existing, nil
}

// promoteToBranch turns a leaf that records nothing into a branch.
//
// A leaf that HOLDS something is NOT promoted. Events, planned events, entries and attachments only
// live on leaves, so converting one would strand its record on a node every event route refuses.
func (n *Node) promoteToBranch() error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if len(n.Events) > 0 || len(n.PlannedEvents) > 0 || len(n.Entries) > 0 || len(n.Attachments) > 0 {
		return fmt.Errorf("cannot add a child to leaf node %s: it already records events or entries", n.Name)
	}

	n.Type = BranchNode
	if n.Children == nil {
		n.Children = make(map[string]*Node)
	}
	return nil
}

// AddParent adds a parent node to the node
func (n *Node) AddParent(parent *Node) {
	if n.Parents == nil {
		n.Parents = make(map[string]string)
	}
	n.Parents[parent.ID] = parent.Name
}

// Add user to the node's Users slice and assign permission
func (node *Node) AddUser(user User, permission Permission) error {
	// Add user to node's Users slice if not already present
	found := false
	for i := range node.Users {
		if node.Users[i].ID == user.ID {
			found = true
			node.Users[i].Permissions = append(node.Users[i].Permissions, permission)
			break
		}
	}
	if !found {
		user.Permissions = []Permission{permission}
		node.Users = append(node.Users, user)
	}
	return nil
}
