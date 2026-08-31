package internal

import (
	"time"

	"github.com/vaziolabs/lumberjack/internal/core"
)

// The shapes an HTTP client is given.
//
// core.User carries the bcrypt hash of the password in a field with a `json:"password"` tag, and a
// core.Node carries its users. So GET /forest, GET /users and GET /forest/tree each handed every
// caller the admin's password hash. These projections are DISTINCT TYPES rather than a copy of the
// live struct with the field blanked: blanking it would mutate the forest the server is still
// serving from, and a projection cannot be forgotten the way a blanking step can.
//
// A field is here because a client needs it. The hash is not one of them.

// userView is a user as a client may see one.
type userView struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Username     string            `json:"username"`
	Email        string            `json:"email"`
	Organization string            `json:"organization"`
	Phone        string            `json:"phone"`
	Permissions  []core.Permission `json:"permissions"`
}

// nodeView is a node as a client may see one, users projected and children projected recursively.
type nodeView struct {
	ID            string                     `json:"id"`
	Type          core.NodeType              `json:"type"`
	Name          string                     `json:"name"`
	Parents       map[string]string          `json:"parents"`
	Children      map[string]nodeView        `json:"children"`
	Events        map[string]core.Event      `json:"events"`
	PlannedEvents map[string]core.Event      `json:"planned_events"`
	Users         []userView                 `json:"users"`
	Entries       []core.Entry               `json:"entries"`
	Attachments   map[string]core.Attachment `json:"attachments,omitempty"`
	CreatedBy     string                     `json:"created_by,omitempty"`
	CreatedAt     time.Time                  `json:"created_at,omitempty"`
	ModifiedBy    string                     `json:"modified_by,omitempty"`
	ModifiedAt    time.Time                  `json:"modified_at,omitempty"`
}

// newUserView projects one user.
func newUserView(user core.User) userView {
	return userView{
		ID:           user.ID,
		Name:         user.Name,
		Username:     user.Username,
		Email:        user.Email,
		Organization: user.Organization,
		Phone:        user.Phone,
		Permissions:  user.Permissions,
	}
}

// newUserViews projects a list of users. An empty list stays an empty list rather than becoming
// JSON null, so a client can iterate the answer without checking it first.
func newUserViews(users []core.User) []userView {
	views := make([]userView, 0, len(users))
	for _, user := range users {
		views = append(views, newUserView(user))
	}
	return views
}

// newNodeView projects a node and everything beneath it.
func newNodeView(node *core.Node) nodeView {
	if node == nil {
		return nodeView{}
	}

	view := nodeView{
		ID:            node.ID,
		Type:          node.Type,
		Name:          node.Name,
		Parents:       node.Parents,
		Children:      make(map[string]nodeView, len(node.Children)),
		Events:        node.Events,
		PlannedEvents: node.PlannedEvents,
		Users:         newUserViews(node.Users),
		Entries:       node.Entries,
		Attachments:   node.Attachments,
		CreatedBy:     node.CreatedBy,
		CreatedAt:     node.CreatedAt,
		ModifiedBy:    node.ModifiedBy,
		ModifiedAt:    node.ModifiedAt,
	}

	for id, child := range node.Children {
		view.Children[id] = newNodeView(child)
	}

	return view
}
