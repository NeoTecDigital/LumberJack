package core

import (
	"fmt"
	"time"
)

// AddActivity adds an activity entry to the node
func (n *Node) AddActivity(content interface{}, metadata map[string]interface{}, userID string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	entry := Entry{
		Content:   content,
		Metadata:  metadata,
		UserID:    userID,
		Timestamp: time.Now(),
	}
	n.Entries = append(n.Entries, entry)
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
		return nil, fmt.Errorf("cannot add a child to leaf node: %s", n.Name)
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
