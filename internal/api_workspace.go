package internal

// The application contract over the existing forest. No parallel datastore:
// work is a node, schedules are events, and logs/time are entries on that node.
import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

type workCommand struct {
	Command      string                 `json:"command"`
	Path         string                 `json:"path"`
	ClientID     string                 `json:"client_id"`
	Revision     string                 `json:"revision,omitempty"`
	Title        string                 `json:"title,omitempty"`
	Kind         string                 `json:"kind,omitempty"`
	Content      string                 `json:"content,omitempty"`
	Status       string                 `json:"status,omitempty"`
	AssignedTo   string                 `json:"assigned_to,omitempty"`
	ParentID     string                 `json:"parent_id,omitempty"`
	EventID      string                 `json:"event_id,omitempty"`
	Start        string                 `json:"start,omitempty"`
	End          string                 `json:"end,omitempty"`
	Username     string                 `json:"username,omitempty"`
	Permission   *int                   `json:"permission,omitempty"`
	Recursive    bool                   `json:"recursive,omitempty"`
	TemplatePath string                 `json:"template_path,omitempty"`
	Preferences  map[string]interface{} `json:"preferences,omitempty"`
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
	for _, member := range node.Users {
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
		if text, ok := entry.Content.(string); ok {
			if text == core.TimeEntryStart {
				active = entry
			}
			if text == core.TimeEntryStop {
				active = nil
			}
		}
	}
	return active
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
		nodes := []map[string]interface{}{}
		visible := map[string]bool{}
		parents := map[string]map[string]string{}
		var active interface{}
		failure = server.walkScope("", nil, func(at visit) {
			if !at.node.CheckPermission(userID, core.ReadPermission) {
				return
			}
			visible[at.node.ID] = true
			parents[at.node.ID] = at.node.Parents
			nodes = append(nodes, server.workView(at.node, at.path, userID))
			if entry := workActive(at.node, userID); entry != nil {
				active = map[string]interface{}{"id": entry.ID, "path": at.path, "started_at": entry.Timestamp}
			}
		})
		for _, node := range nodes {
			ids := []string{}
			for id := range parents[node["id"].(string)] {
				if visible[id] {
					ids = append(ids, id)
				}
			}
			sort.Strings(ids)
			node["parent_ids"] = ids
		}
		body, err = json.Marshal(map[string]interface{}{"user": map[string]interface{}{"id": profile.ID,
			"username": profile.Username, "admin": server.forest.CheckPermission(userID, core.AdminPermission)},
			"nodes": nodes, "active_timer": active})
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

// ApplyWorkCommand validates, commits and acknowledges one application command.
func (server *Server) ApplyWorkCommand(userID string, cmd WorkCommand) ([]byte, error) {
	if cmd.Path == "" || cmd.ClientID == "" || len(cmd.ClientID) > 100 {
		return nil, apiErrorf(400, "A target and command identity are required")
	}
	digestBytes, _ := json.Marshal(cmd)
	digest := fmt.Sprintf("%x", sha256.Sum256(digestBytes))
	var response []byte
	changedPath := cmd.Path
	mutationKind := mutationMetadataSet
	var additional []mutationEvent
	committed := false
	err := server.changeForest(func() error {
		node, err := server.getNodeFromPath(cmd.Path)
		if err != nil {
			return apiErrorf(404, "Work was not found")
		}
		initializing := cmd.Command == "initialize" && node == server.forest
		if !initializing && !node.CheckPermission(userID, core.WritePermission) {
			return apiErrorf(403, "You can view this work but cannot change it")
		}
		if node.Metadata == nil {
			node.Metadata = map[string]interface{}{}
		}
		receipts := node.CommandReceipts
		if receipts == nil {
			receipts = map[string]interface{}{}
		}
		receiptKey := userID + ":" + cmd.ClientID
		if previous, ok := receipts[receiptKey].(map[string]interface{}); ok {
			if previous["digest"] != digest {
				return apiErrorf(409, "This command identity was already used")
			}
			response, _ = json.Marshal(previous["result"])
			return nil
		}
		if cmd.Command == "update" && (cmd.Revision == "" || cmd.Revision != workRevision(node)) {
			return apiErrorf(409, "This work changed while you were editing. Reload its latest version before saving your draft.")
		}
		if server.forest.Correspondence != nil && len(server.forest.Correspondence.Pending) >= 4096 {
			return apiErrorf(503, "Change delivery is behind. Try again shortly.")
		}
		var result interface{}
		switch cmd.Command {
		case "initialize":
			if node != server.forest {
				return apiErrorf(400, "Initialize from the workspace root")
			}
			result, err = server.workInitialize(userID)
			if err != nil {
				return err
			}
			mutationKind = mutationNodeCreated
		case "preferences":
			if err := workPreferences(node, userID, cmd.Preferences); err != nil {
				return err
			}
		case "event_transition":
			if err := workTransition(node, userID, cmd.EventID, cmd.Status); err != nil {
				return err
			}
			mutationKind = mutationEventStarted
		case "create":
			if strings.TrimSpace(cmd.Title) == "" || len(cmd.Title) > 200 {
				return apiErrorf(400, "Name your work (up to 200 characters)")
			}
			if !workKind(cmd.Kind) {
				return apiErrorf(400, "Choose an idea, goal, action, procedure, workflow, or document")
			}
			child, err := server.workChild(node, cmd.Title, cmd.Kind, userID)
			if err != nil {
				return err
			}
			changedPath = server.canonicalPath(cmd.Path) + "/" + child.Name
			result = map[string]interface{}{"id": child.ID, "path": changedPath}
			mutationKind = mutationNodeCreated
		case "update":
			if strings.TrimSpace(cmd.Title) == "" || len(cmd.Title) > 200 {
				return apiErrorf(400, "Name your work (up to 200 characters)")
			}
			if !workKind(cmd.Kind) || !workStatus(cmd.Status) {
				return apiErrorf(400, "Unknown work kind or status")
			}
			if cmd.AssignedTo != "" && !node.CheckPermission(cmd.AssignedTo, core.ReadPermission) {
				return apiErrorf(400, "Assign work to one of its members")
			}
			node.Kind = cmd.Kind
			node.Metadata["title"], node.Metadata["description"] = cmd.Title, cmd.Content
			node.Metadata["status"], node.Metadata["assigned_to"] = cmd.Status, cmd.AssignedTo
		case "log":
			if cmd.Content == core.TimeEntryStart || cmd.Content == core.TimeEntryStop {
				return apiErrorf(400, "Use the timer controls to record a time boundary")
			}
			if strings.TrimSpace(cmd.Content) == "" {
				return apiErrorf(400, "Write something to log")
			}
			if cmd.ParentID != "" {
				found := false
				for _, entry := range node.Entries {
					if entry.ID == cmd.ParentID {
						found = true
					}
				}
				if !found {
					return apiErrorf(400, "The reply target is not on this work")
				}
			}
			entry := node.AddEntry(cmd.Content, map[string]interface{}{"client_id": cmd.ClientID, "category": "log"}, userID, cmd.ParentID, "")
			result = newEntryView(entry)
			mutationKind = mutationEntryAdded
		case "timer_start":
			var activePath string
			_ = server.walkScope("", nil, func(at visit) {
				if workActive(at.node, userID) != nil {
					activePath = at.path
				}
			})
			if activePath != "" {
				return apiErrorf(409, "Stop your timer on %s before starting another", activePath)
			}
			eventID := cmd.EventID
			if eventID == "" {
				eventID = cmd.ClientID
			}
			var metadata map[string]interface{}
			if cmd.EventID == "" {
				metadata = map[string]interface{}{"title": node.Metadata["title"]}
			}
			if err := node.StartEvent(eventID, userID, nil, nil, metadata); err != nil {
				return apiErrorf(409, "%v", err)
			}
			event := node.Events[eventID]
			event.Realizes, event.AssignedTo = node.ID, userID
			node.Events[eventID] = event
			node.Metadata["status"] = "active"
			entry := node.AddEntry(core.TimeEntryStart, map[string]interface{}{"client_id": cmd.ClientID, "event_id": eventID}, userID, "", "")
			result = newEntryView(entry)
			mutationKind = mutationEntryAdded
		case "timer_stop":
			active := workActive(node, userID)
			if active == nil || active.ID != cmd.EventID {
				return apiErrorf(409, "That timer is no longer running. Refresh to see the current timer.")
			}
			eventID, _ := active.Metadata["event_id"].(string)
			if event, exists := node.Events[eventID]; exists && event.EndTime == nil {
				if err := node.EndEvent(eventID, userID); err != nil {
					return apiErrorf(409, "%v", err)
				}
			}
			entry := node.AddEntry(core.TimeEntryStop, map[string]interface{}{"event_id": eventID}, userID, "", "")
			result = newEntryView(entry)
			mutationKind = mutationEntryAdded
		case "time":
			start, end, err := workInterval(cmd.Start, cmd.End)
			if err != nil {
				return err
			}
			if end.After(time.Now()) {
				return apiErrorf(400, "Logged time must be in the past")
			}
			if workActive(node, userID) != nil {
				return apiErrorf(409, "Stop the active timer before adding a manual interval")
			}
			for _, span := range node.GetTimeTrackingSummary(userID) {
				from, a := span["start_time"].(time.Time)
				to, b := span["end_time"].(time.Time)
				if a && b && start.Before(to) && end.After(from) {
					return apiErrorf(409, "This interval overlaps time already logged here")
				}
			}
			if _, exists := node.Events[cmd.ClientID]; exists {
				return apiErrorf(409, "This event identity already exists")
			}
			node.Events[cmd.ClientID] = core.Event{StartTime: &start, EndTime: &end, Status: core.EventFinished,
				Realizes: node.ID, AssignedTo: userID, CreatedBy: userID, CreatedAt: time.Now(), ModifiedBy: userID, ModifiedAt: time.Now(),
				Metadata: map[string]interface{}{"title": cmd.Title, "manual": true}}
			first := node.AddEntry(core.TimeEntryStart, map[string]interface{}{"manual": true, "event_id": cmd.ClientID}, userID, "", "")
			node.Entries[len(node.Entries)-1].Timestamp = start
			node.AddEntry(core.TimeEntryStop, map[string]interface{}{"manual": true, "event_id": cmd.ClientID}, userID, "", "")
			node.Entries[len(node.Entries)-1].Timestamp = end
			sort.SliceStable(node.Entries, func(i, j int) bool { return node.Entries[i].Timestamp.Before(node.Entries[j].Timestamp) })
			result = map[string]interface{}{"id": first.ID}
			mutationKind = mutationEntryAdded
		case "plan":
			if cmd.EventID != "" {
				if _, exists := node.PlannedEvents[cmd.EventID]; exists && cmd.Revision != workRevision(node) {
					return apiErrorf(409, "Reload the latest plan before rescheduling it")
				}
			}
			start, end, err := workInterval(cmd.Start, cmd.End)
			if err != nil {
				return err
			}
			eventID := cmd.EventID
			if eventID == "" {
				eventID = cmd.ClientID
			}
			if cmd.AssignedTo != "" && !node.CheckPermission(cmd.AssignedTo, core.ReadPermission) {
				return apiErrorf(400, "Assign the plan to a member")
			}
			if err := node.PlanEvent(eventID, userID, &start, &end, map[string]interface{}{"title": cmd.Title}); err != nil {
				return apiErrorf(409, "%v", err)
			}
			planned := node.PlannedEvents[eventID]
			planned.Realizes = node.ID
			planned.AssignedTo = cmd.AssignedTo
			node.PlannedEvents[eventID] = planned
			result = map[string]interface{}{"event_id": eventID}
			mutationKind = mutationEventPlanned
		case "share":
			if node == server.forest {
				return apiErrorf(400, "Share a workspace or work item; account access is managed separately")
			}
			if !node.CheckPermission(userID, core.AdminPermission) {
				return apiErrorf(403, "Only an owner can change members")
			}
			if cmd.Permission == nil || *cmd.Permission < -1 || *cmd.Permission > 2 {
				return apiErrorf(400, "Choose a valid permission")
			}
			var memberID string
			for _, user := range server.forest.Users {
				if user.Username == cmd.Username {
					memberID = user.ID
				}
			}
			if memberID == "" {
				return apiErrorf(404, "No account with that username")
			}
			if memberID == userID && *cmd.Permission < 2 {
				return apiErrorf(409, "Ask another owner to change your access")
			}
			targets := []*core.Node{node}
			if cmd.Recursive {
				targets = nil
				_ = server.walkScope(cmd.Path, nil, func(at visit) { targets = append(targets, at.node) })
			}
			for _, target := range targets {
				if !target.CheckPermission(userID, core.AdminPermission) {
					return apiErrorf(403, "You must own every included item to change access to the subtree")
				}
			}
			for _, target := range targets {
				// Revoking edit access must not strand a user's global active timer.
				if *cmd.Permission < 1 {
					if active := workActive(target, memberID); active != nil {
						eventID, _ := active.Metadata["event_id"].(string)
						if event, exists := target.Events[eventID]; exists && event.EndTime == nil {
							now := time.Now()
							event.EndTime, event.Status = &now, core.EventFinished
							event.ModifiedBy, event.ModifiedAt = userID, now
							target.Events[eventID] = event
						}
						target.AddEntry(core.TimeEntryStop, map[string]interface{}{"event_id": eventID, "stopped_by": userID, "reason": "access_changed"}, memberID, "", "")
						_ = server.walkScope("", nil, func(at visit) {
							if at.node == target {
								ended := mutation(mutationEventEnded, at.path)
								ended.EventID = eventID
								additional = append(additional, ended, mutation(mutationEntryAdded, at.path))
							}
						})
					}
				}
				kept := []core.User{}
				for _, user := range target.Users {
					if user.ID != memberID {
						kept = append(kept, user)
					}
				}
				if *cmd.Permission >= 0 {
					kept = append(kept, core.User{ID: memberID, Permissions: []core.Permission{core.Permission(*cmd.Permission)}})
				}
				target.Users = kept
			}
		case "run":
			result, err = server.workRun(node, cmd.TemplatePath, userID)
			if err != nil {
				return err
			}
			mutationKind = mutationNodeCreated
		default:
			return apiErrorf(400, "Unknown workspace command")
		}
		node.ModifiedBy, node.ModifiedAt = userID, time.Now().UTC()
		answer := map[string]interface{}{"client_id": cmd.ClientID, "path": changedPath, "result": result}
		if len(receipts) >= 256 {
			oldestKey, oldestTime := "", ""
			for key, value := range receipts {
				receipt, _ := value.(map[string]interface{})
				at, _ := receipt["at"].(string)
				if oldestKey == "" || at < oldestTime {
					oldestKey, oldestTime = key, at
				}
			}
			delete(receipts, oldestKey)
		}
		receipts[receiptKey] = map[string]interface{}{"digest": digest, "result": answer, "at": time.Now().UTC().Format(time.RFC3339Nano)}
		node.CommandReceipts = receipts
		server.enqueueCorrespondence(userID, cmd, changedPath)
		committed = true
		response, err = json.Marshal(answer)
		return err
	})
	if err != nil {
		return nil, err
	}
	if committed {
		server.publish(mutation(mutationKind, changedPath))
		for _, event := range additional {
			server.publish(event)
		}
	}
	return response, nil
}

func workKind(kind string) bool {
	switch kind {
	case "idea", "goal", "action", "procedure", "workflow", "document", "run", "workspace", "collection":
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
	if parent != server.forest {
		for _, member := range parent.Users {
			if member.ID == userID {
				continue
			}
			child.AssignUser(core.User{ID: member.ID}, core.Permission(workPermission(parent, member.ID)))
		}
	}
	return child, nil
}

func (server *Server) workRun(parent *core.Node, templatePath, userID string) (interface{}, error) {
	template, err := server.getNodeFromPath(templatePath)
	if err != nil || !template.CheckPermission(userID, core.ReadPermission) {
		return nil, apiErrorf(404, "Procedure not found")
	}
	if template.Kind != "procedure" && template.Kind != "workflow" {
		return nil, apiErrorf(400, "Choose a procedure or workflow")
	}
	// Snapshot the complete definition before creating a run. Shared steps remain shared
	// within a run, and later template edits never change an existing run.
	definitions := map[string]*core.Node{}
	var ordered []*core.Node
	var inspect func(*core.Node) error
	inspect = func(step *core.Node) error {
		if definitions[step.ID] != nil {
			return nil
		}
		if len(definitions) >= 1000 {
			return apiErrorf(400, "A workflow can contain at most 1000 items")
		}
		if !step.CheckPermission(userID, core.ReadPermission) {
			return apiErrorf(403, "You must be able to read every workflow step")
		}
		definitions[step.ID] = step
		ordered = append(ordered, step)
		for _, child := range childrenByName(step) {
			if err := inspect(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := inspect(template); err != nil {
		return nil, err
	}
	versionParts := []interface{}{}
	for _, step := range ordered {
		edges := []string{}
		for _, child := range childrenByName(step) {
			edges = append(edges, child.ID)
		}
		versionParts = append(versionParts, []interface{}{step.ID, step.Kind, workMetadata(step), edges})
	}
	definition, _ := json.Marshal(versionParts)
	version := fmt.Sprintf("%x", sha256.Sum256(definition))
	title, _ := template.Metadata["title"].(string)
	if title == "" {
		title = template.Name
	}
	run, err := server.workChild(parent, title+" · run", "run", userID)
	if err != nil {
		return nil, err
	}
	run.Metadata["procedure_id"], run.Metadata["procedure_revision"], run.Metadata["status"] = template.ID, version, "active"
	clones := map[string]*core.Node{template.ID: run}
	var cloneChildren func(*core.Node, *core.Node) error
	cloneChildren = func(source, target *core.Node) error {
		// Read edges from the captured definition, before this run can be included.
		for index, step := range childrenByName(source) {
			if definitions[step.ID] == nil {
				continue
			}
			if existing := clones[step.ID]; existing != nil {
				target.AddChild(existing)
				continue
			}
			label, _ := step.Metadata["title"].(string)
			if label == "" {
				label = step.Name
			}
			child, err := server.workChild(target, label, "action", userID)
			if err != nil {
				return err
			}
			clones[step.ID] = child
			child.Metadata["procedure_step_id"], child.Metadata["order"], child.Metadata["status"] = step.ID, index, "planned"
			child.Metadata["description"] = copyValue(step.Metadata["description"])
			if err := cloneChildren(step, child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := cloneChildren(template, run); err != nil {
		return nil, err
	}
	return map[string]interface{}{"id": run.ID}, nil
}
