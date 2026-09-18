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

	// No Type check: a node holds children AND events/entries at once (phase 18.3, see NodeType), so
	// a leaf that already records something can still gain a child. It once refused a non-branch here,
	// which is what made category{goal{routine{event}}} structurally illegal.

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
// Such a segment HOLDS a child, so an existing node of that name — whatever its type, recording
// whatever it records — is returned and given the branch VIEW HINT, and only a missing one is
// created. It once refused a leaf that recorded events, which is the leaf-only invariant phase 18.3
// removed: a node holds children and events at once now, so nothing needs promoting in order to hold
// a child, and the hint is set only so the node reads as a branch by default. See NodeType.
func (n *Node) AddBranchChild(name string, userID string) (*Node, error) {
	existing := n.ChildNamed(name)
	if existing == nil {
		return n.AddChildNode(name, BranchNode, userID)
	}
	existing.markBranch()
	return existing, nil
}

// markBranch sets a node's advisory branch view hint and makes sure its Children map exists.
//
// It NEVER refuses. promoteToBranch, which it replaces, rejected a node that already recorded events
// or entries — to keep a record off a node the event routes would not serve, which was the leaf-only
// invariant phase 18.3 removed. It is idempotent: a node already carrying the branch hint is
// unchanged, and one that also holds events keeps them. Type is only a default view hint now, so
// this changes how a node is drawn by default and nothing about what it may hold (see NodeType).
func (n *Node) markBranch() {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.Type = BranchNode
	if n.Children == nil {
		n.Children = make(map[string]*Node)
	}
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
