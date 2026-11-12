package internal

// The application contract over the existing forest. No parallel datastore:
// work is a node, schedules are events, and logs/time are entries on that node.
import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/NeoTecDigital/LumberJack/core"
)

type workCommand struct {
	Tags            *[]string              `json:"tags,omitempty"`
	Priority        *string                `json:"priority,omitempty"`
	Progress        *float64               `json:"progress,omitempty"`
	FinancialTarget *workMoney             `json:"financial_target,omitempty"`
	Asset           *workAsset             `json:"asset,omitempty"`
	Required        bool                   `json:"required,omitempty"`
	Temporal        *temporalInput         `json:"temporal,omitempty"`
	ExampleVersion  int                    `json:"example_version,omitempty"`
	CategoryIDs     *[]string              `json:"category_ids,omitempty"`
	Categories      *[]string              `json:"categories,omitempty"`
	Shared          bool                   `json:"shared,omitempty"`
	Subscribed      bool                   `json:"subscribed,omitempty"`
	Command         string                 `json:"command"`
	Path            string                 `json:"path"`
	ClientID        string                 `json:"client_id"`
	Revision        string                 `json:"revision,omitempty"`
	Title           string                 `json:"title,omitempty"`
	Kind            string                 `json:"kind,omitempty"`
	Content         string                 `json:"content,omitempty"`
	Status          string                 `json:"status,omitempty"`
	AssignedTo      string                 `json:"assigned_to,omitempty"`
	ParentID        string                 `json:"parent_id,omitempty"`
	EventID         string                 `json:"event_id,omitempty"`
	Start           string                 `json:"start,omitempty"`
	End             string                 `json:"end,omitempty"`
	Username        string                 `json:"username,omitempty"`
	Permission      *int                   `json:"permission,omitempty"`
	Recursive       bool                   `json:"recursive,omitempty"`
	TemplatePath    string                 `json:"template_path,omitempty"`
	Preferences     map[string]interface{} `json:"preferences,omitempty"`
}

func workPermission(node *core.Node, userID string) int {
	for p := 2; p >= 0; p-- {
		if node.CheckPermission(userID, core.Permission(p)) {
			return p
		}
	}
	return -1
}

func workMetadata(node *core.Node) map[string]interface{} {
	metadata := map[string]interface{}{}
	for key, value := range node.Metadata {
		if key != "momentum.receipts" {
			metadata[key] = value
		}
	}
	return metadata
}

func workRevision(node *core.Node) string {
	data, _ := json.Marshal([]interface{}{node.Kind, workMetadata(node), newEntryViews(node.Entries),
		newEventViews(node.Events), newEventViews(node.PlannedEvents), newAttachmentViews(node.Attachments), newUserViews(node.Users)})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func (server *Server) workView(node *core.Node, path, userID string) map[string]interface{} {
	members := []map[string]interface{}{}
	for _, member := range server.forest.Users {
		if node != server.forest && !node.CheckPermission(member.ID, core.ReadPermission) {
			continue
		}
		// Account inventory is not a resource membership list.
		if node == server.forest && member.ID != userID && !node.CheckPermission(userID, core.AdminPermission) {
			continue
		}
		profile, err := server.forest.GetUserProfile(member.ID)
		if err != nil {
			continue
		}
		members = append(members, map[string]interface{}{"id": member.ID, "username": profile.Username,
			"permission": workPermission(node, member.ID)})
	}
	return map[string]interface{}{"id": node.ID, "path": path, "name": node.Name, "kind": node.Kind,
		"creation_audience": server.creationAudience(node, userID),
		"subscribed":        server.forest.Subscriptions[userID][node.ID],
		"created_by":        node.CreatedBy, "created_at": node.CreatedAt,
		"metadata": workMetadata(node), "revision": workRevision(node), "permission": workPermission(node, userID),
		"members": members, "entries": newEntryViews(node.Entries), "events": newEventViews(node.Events),
		"planned_events": newEventViews(node.PlannedEvents), "attachments": newAttachmentViews(node.Attachments)}
}

// Must be called under the forest hold. An active span is derived from the same
// sentinels as existing time queries, and survives restarts without local storage.
func workActive(node *core.Node, userID string) *core.Entry {
	var active *core.Entry
	for i := range node.Entries {
		entry := &node.Entries[i]
		if entry.UserID != userID {
			continue
		}
		switch workTimeBoundary(entry) {
		case core.TimeEntryStart:
			active = entry
		case core.TimeEntryStop:
			active = nil
		}
	}
	return active
}
func workTimeBoundary(entry *core.Entry) string {
	value, _ := entry.Content.(string)
	return value
}

func (server *Server) handleWorkspace(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "Sign in required", 401)
		return
	}
	body, err := server.Workspace(userID)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// Workspace is the permission-filtered snapshot shared by HTTP and native callers.
func (server *Server) Workspace(userID string) ([]byte, error) {
	var body []byte
	var failure error
	server.readForest(func() {
		profile, err := server.forest.GetUserProfile(userID)
		if err != nil {
			failure = apiErrorf(401, "Account unavailable")
			return
		}
		projection := workSnapshot{server: server, user: userID, nodes: []map[string]interface{}{}, visible: map[string]bool{}, parents: map[string]map[string]string{}}
		failure = server.walkScope("", nil, projection.visit)
		workParentViews(projection.nodes, projection.parents, projection.visible)
		body, err = json.Marshal(map[string]interface{}{"user": map[string]interface{}{"id": profile.ID,
			"username": profile.Username, "admin": server.forest.CheckPermission(userID, core.AdminPermission)},
			"nodes": projection.nodes, "active_timer": projection.active})
		if err != nil {
			failure = err
		}
	})
	return body, failure
}

// WorkCommand is the typed application mutation shared with the embedded runtime.
type WorkCommand = workCommand

func (server *Server) handleWorkCommand(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "Sign in required", 401)
		return
	}
	var cmd WorkCommand
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cmd); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	body, err := server.ApplyWorkCommand(userID, cmd)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func workKind(kind string) bool {
	switch kind {
	case "asset", "idea", "project", "category", "goal", "action", "procedure", "workflow", "document", "run", "workspace", "collection", "conversation":
		return true
	}
	return false
}
func workStatus(status string) bool {
	switch status {
	case "idea", "planned", "active", "blocked", "done", "cancelled":
		return true
	}
	return false
}
func workInterval(from, to string) (time.Time, time.Time, error) {
	start, a := time.Parse(time.RFC3339, from)
	end, b := time.Parse(time.RFC3339, to)
	if a != nil || b != nil || !end.After(start) {
		return start, end, apiErrorf(400, "Choose an end after the start, with a timezone")
	}
	return start, end, nil
}

func (server *Server) workChild(parent *core.Node, title, kind, userID string) (*core.Node, error) {
	name := "work-" + core.GenerateEntryID()
	child, err := parent.AddChildNode(name, core.BranchNode, userID)
	if err != nil {
		return nil, apiErrorf(400, "%v", err)
	}
	child.Kind = kind
	// The forest's user inventory is not an invitation to newly created work.
	child.Users = []core.User{{ID: userID, Permissions: []core.Permission{core.AdminPermission}}}
	child.Metadata = map[string]interface{}{"title": title, "status": "idea", "intent_id": parent.ID}
	server.defaultWorkSubscriptions(child, userID)
	return child, nil
}

func workParentViews(nodes []map[string]interface{}, parents map[string]map[string]string, visible map[string]bool) {
	for _, node := range nodes {
		node["parent_ids"] = workVisibleParents(parents[node["id"].(string)], visible)
	}
}
func workVisibleParents(parents map[string]string, visible map[string]bool) []string {
	ids := []string{}
	for id := range parents {
		if visible[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

type workSnapshot struct {
	server  *Server
	user    string
	nodes   []map[string]interface{}
	visible map[string]bool
	parents map[string]map[string]string
	active  interface{}
}

func (snapshot *workSnapshot) visit(at visit) {
	if !at.node.CheckPermission(snapshot.user, core.ReadPermission) {
		return
	}
	snapshot.visible[at.node.ID] = true
	snapshot.parents[at.node.ID] = at.node.Parents
	snapshot.nodes = append(snapshot.nodes, snapshot.server.workView(at.node, at.path, snapshot.user))
	if entry := workActive(at.node, snapshot.user); entry != nil {
		snapshot.active = map[string]interface{}{"id": entry.ID, "path": at.path, "started_at": entry.Timestamp}
	}
}
