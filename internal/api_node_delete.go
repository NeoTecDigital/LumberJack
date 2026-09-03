package internal

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/vaziolabs/lumberjack/internal/core"
)

// DELETE /nodes/{path} — remove a NODE. Not an edge.
//
// THE DISTINCTION THIS ROUTE IS BUILT AROUND. Under the multi-parent model a node reachable by two
// parents is the ordinary case, not a corner: one person's work belongs to their own tree and to an
// organisation's at the same time. For such a node "delete it" names two different operations —
// remove the node from the forest, or remove the edge you arrived through — and a route that
// guesses between them destroys the other organisation's work on a request that read like tidying
// up. So this route does not guess: a node with more than one parent is REFUSED, and the refusal
// names DELETE /nodes/link, which is the operation for the edge and has existed all along. A caller
// that means the node unlinks the other arms first, each one an explicit act with its own
// permission check and its own place in the feed.
//
// WHAT IT DOES WITH WHAT IS UNDER AND INSIDE THE NODE — `mode`, defaulting to `refuse`.
//
//	refuse  — the node must hold NOTHING: no children, no events, no planned events, no entries,
//	          no attachments. This is the default because it is the operation that cannot surprise
//	          anyone: it removes exactly the thing that was named and nothing else, which is what
//	          pruning a mis-drawn node off a canvas is. A node that holds something is answered 409
//	          saying what it holds, so the caller can decide rather than discover.
//	cascade — the node and its subtree go, and the events, entries and attachment BYTES they held
//	          go with them. An attachment is stored inside the node's own document, so there is no
//	          orphaned blob store to sweep afterwards; the bytes are gone when the document is.
//
// A DESCENDANT THAT IS ALSO SOMEBODY ELSE'S IS NOT CASCADED INTO. A cascade removes only the
// descendants whose every parent is itself being removed; a descendant that hangs off a node
// outside the subtree loses that ONE edge and keeps its other parents, so it stays reachable and
// nothing is stranded. That is the same invariant DELETE /nodes/link enforces when it refuses to
// remove a node's last parent, applied to a bulk operation.
//
// HARD DELETE, NOT A TOMBSTONE. The state file is ONE document, rewritten in full under the
// exclusive forest hold on every single mutation — so a tombstone is not paid for once, it is paid
// for on every future write by every future request, which is exactly the cost the flat node table
// was introduced to remove. The audit trail is not in the document: it is in the mutation feed,
// which numbers and timestamps every removal, and in the log, which records who removed what. The
// forest is the working set; the history belongs where history is appended, not in the file that is
// rewritten whole.

// The modes this route accepts. The default is the one that cannot remove anything the caller did
// not name.
const (
	deleteModeRefuse  = "refuse"
	deleteModeCascade = "cascade"
)

// nodeRemoval is what a delete did, counted while the forest was still held.
type nodeRemoval struct {
	Path        string   `json:"path"`
	Mode        string   `json:"mode"`
	NodeCount   int      `json:"nodes_removed"`
	Paths       []string `json:"paths_removed"`
	Events      int      `json:"events_removed"`
	Entries     int      `json:"entries_removed"`
	Attachments int      `json:"attachments_removed"`
}

func (server *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("DeleteNode")
	defer server.logger.Exit("DeleteNode")

	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	mode, err := deleteModeOf(r.URL.Query().Get("mode"))
	if err != nil {
		writeAPIError(w, err)
		return
	}

	path := strings.Trim(mux.Vars(r)["path"], "/")
	removed, err := server.removeNodeUnderHold(path, mode, userID)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	// ONE ANNOUNCEMENT PER REMOVED NODE, not one for the request. A client caches per node path, so
	// a cascade that announced only the node the caller named would leave every descendant's
	// projection cacheable and correct-looking forever.
	for _, gone := range removed.Paths {
		server.publish(mutation(mutationNodeDeleted, gone))
	}
	server.logger.Success("Deleted %d node(s) at %s (%s) for %s", removed.NodeCount, removed.Path, mode, userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(removed)
}

// deleteModeOf reads the mode. An unnamed mode is `refuse`, and an unknown one is a REFUSAL rather
// than a silent fallback to it: a caller that misspells `cascade` must not be told the node holds
// something when what it actually did was ask for a mode this route does not have.
func deleteModeOf(raw string) (string, error) {
	switch raw {
	case "", deleteModeRefuse:
		return deleteModeRefuse, nil
	case deleteModeCascade:
		return deleteModeCascade, nil
	default:
		return "", apiErrorf(http.StatusBadRequest,
			"unknown mode %q: use %q or %q", raw, deleteModeRefuse, deleteModeCascade)
	}
}

// removeNodeUnderHold resolves the node, decides what may go, removes it, and persists — all under
// one exclusive hold, so nothing can link a new child under a node that is being removed.
func (server *Server) removeNodeUnderHold(path, mode, userID string) (nodeRemoval, error) {
	removed := nodeRemoval{Mode: mode}

	err := server.changeForest(func() error {
		node, err := server.getNodeFromPath(path)
		if err != nil {
			return apiErrorf(http.StatusNotFound, "%v", err)
		}
		parent, err := server.parentForDeletion(node, path)
		if err != nil {
			return err
		}

		doomed, err := server.doomedFor(node, path, mode)
		if err != nil {
			return err
		}
		if err := writableThroughout(doomed, parent, userID); err != nil {
			return err
		}

		removed = detach(doomed, parent)
		removed.Mode = mode
		removed.Path = server.canonicalPath(path)
		return nil
	})
	return removed, err
}

// parentForDeletion is the one parent the node hangs off, and the refusals that make "one" true.
//
// THE ROOT is refused: it has no parent, every user is granted on it, and removing it is emptying
// the database through a route whose name says it removes a node.
//
// A NODE WITH TWO PARENTS is refused, and this is the decision this route exists to make. See the
// file comment: the two operations are different and the API must not conflate them.
func (server *Server) parentForDeletion(node *core.Node, path string) (*core.Node, error) {
	if node == server.forest {
		return nil, apiErrorf(http.StatusConflict,
			"%s is the forest root and cannot be deleted", node.Name)
	}
	if len(node.Parents) > 1 {
		return nil, apiErrorf(http.StatusConflict,
			"%s has %d parents: deleting it would remove it from all of them. "+
				"Use DELETE /nodes/link to remove the edge you arrived through, "+
				"or unlink the others first if you mean the node",
			node.Name, len(node.Parents))
	}

	segments := server.segmentsFrom(path)
	parent, err := server.getNodeFromPath(strings.Join(segments[:len(segments)-1], "/"))
	if err != nil {
		return nil, apiErrorf(http.StatusNotFound, "parent of %s: %v", path, err)
	}
	if _, linked := parent.Children[node.ID]; !linked {
		return nil, apiErrorf(http.StatusConflict, "%s is not under %s", node.Name, parent.Name)
	}
	return parent, nil
}

// doomedFor is every node this request removes, each with the path it is announced under.
func (server *Server) doomedFor(node *core.Node, path, mode string) ([]visit, error) {
	at := visit{node: node, path: server.canonicalPath(path)}
	if mode == deleteModeCascade {
		return cascadeFrom(at), nil
	}

	if held := heldBy(node); held != "" {
		return nil, apiErrorf(http.StatusConflict,
			"%s holds %s: delete them first, or ask for mode=%s", node.Name, held, deleteModeCascade)
	}
	return []visit{at}, nil
}

// heldBy names what a node is holding, or "" if it holds nothing. It is the refusal's TEXT as well
// as its condition, so the two cannot come to disagree about what "empty" means.
func heldBy(node *core.Node) string {
	var held []string
	if len(node.Children) > 0 {
		held = append(held, plural(len(node.Children), "child", "children"))
	}
	if count := len(node.Events) + len(node.PlannedEvents); count > 0 {
		held = append(held, plural(count, "event", "events"))
	}
	if len(node.Entries) > 0 {
		held = append(held, plural(len(node.Entries), "entry", "entries"))
	}
	if len(node.Attachments) > 0 {
		held = append(held, plural(len(node.Attachments), "attachment", "attachments"))
	}
	return strings.Join(held, ", ")
}

// cascadeFrom is the subtree that may go: the node, and every descendant whose EVERY parent is
// itself going.
//
// A descendant with a parent outside the set is left alone — it stays reachable through that
// parent, and only the edge into the removed subtree goes. That is what keeps a cascade from
// stranding somebody else's node, and it is the same rule DELETE /nodes/link enforces one edge at
// a time.
//
// A node whose last doomed parent is popped after it was first considered is RE-CONSIDERED then,
// because it is reached again through that parent's children. So the set is complete without a
// second pass, and each edge is examined once per parent.
//
// The caller must hold the forest exclusively.
func cascadeFrom(root visit) []visit {
	doomed := map[string]bool{root.node.ID: true}
	found := []visit{root}
	queue := []visit{root}

	for len(queue) > 0 {
		at := queue[0]
		queue = queue[1:]

		for _, child := range childrenByName(at.node) {
			if doomed[child.ID] || !allParentsDoomed(child, doomed) {
				continue
			}
			doomed[child.ID] = true
			below := visit{node: child, path: at.path + "/" + child.Name, depth: at.depth + 1}
			found = append(found, below)
			queue = append(queue, below)
		}
	}
	return found
}

// allParentsDoomed reports whether nothing outside the removed set still holds this node.
func allParentsDoomed(node *core.Node, doomed map[string]bool) bool {
	for parentID := range node.Parents {
		if !doomed[parentID] {
			return false
		}
	}
	return true
}

// writableThroughout refuses unless the caller may write EVERY node being removed, and the parent
// that loses a child.
//
// Every one of them, not just the one that was named: a cascade removes nodes the caller did not
// name, and a permission that was never granted on those is not granted by naming an ancestor. The
// parent is checked because losing a child is a change to it — which is what DELETE /nodes/link
// already checks both ends for.
func writableThroughout(doomed []visit, parent *core.Node, userID string) error {
	if parent != nil && !parent.CheckPermission(userID, core.WritePermission) {
		return apiErrorf(http.StatusForbidden, "Insufficient permissions on %s", parent.Name)
	}
	for _, at := range doomed {
		if !at.node.CheckPermission(userID, core.WritePermission) {
			return apiErrorf(http.StatusForbidden, "Insufficient permissions on %s", at.node.Name)
		}
	}
	return nil
}

// detach removes the doomed nodes from the graph and reports what went with them.
//
// Both directions of every edge are cut: a Parents entry left behind on a surviving child names a
// node that no longer exists, and the projection reports parent ids straight out of that map.
//
// The caller must hold the forest exclusively.
func detach(doomed []visit, parent *core.Node) nodeRemoval {
	byID := make(map[string]*core.Node, len(doomed)+1)
	for _, at := range doomed {
		byID[at.node.ID] = at.node
	}
	if parent != nil {
		byID[parent.ID] = parent
	}

	removed := nodeRemoval{NodeCount: len(doomed), Paths: make([]string, 0, len(doomed))}
	// The addressed node is cut from its parent EXPLICITLY, and not only through its own Parents
	// map. The two are supposed to agree, and the loop below relies on them agreeing for every
	// descendant — but for the node the caller actually named, the parent is the one this request
	// resolved by walking the path, and a Parents map that has lost an entry it should carry would
	// otherwise leave the node hanging off a parent that still lists it as a child.
	if parent != nil && len(doomed) > 0 {
		delete(parent.Children, doomed[0].node.ID)
	}

	for _, at := range doomed {
		removed.Paths = append(removed.Paths, at.path)
		countInto(&removed, at.node)

		for parentID := range at.node.Parents {
			if holder, known := byID[parentID]; known {
				delete(holder.Children, at.node.ID)
			}
			delete(at.node.Parents, parentID)
		}
		for childID, child := range at.node.Children {
			// A surviving child: it keeps every other parent, so it is still reachable.
			delete(child.Parents, at.node.ID)
			delete(at.node.Children, childID)
		}
	}
	return removed
}

// countInto adds what one node was holding to the report.
func countInto(removed *nodeRemoval, node *core.Node) {
	removed.Events += len(node.Events) + len(node.PlannedEvents)
	removed.Entries += len(node.Entries)
	removed.Attachments += len(node.Attachments)

	for _, entry := range node.Entries {
		removed.Attachments += len(entry.Attachments)
	}
	for _, events := range []map[string]core.Event{node.Events, node.PlannedEvents} {
		for _, event := range events {
			removed.Entries += len(event.Entries)
			for _, entry := range event.Entries {
				removed.Attachments += len(entry.Attachments)
			}
		}
	}
}

// plural renders a count with the right noun, because a refusal that says "1 children" reads like a
// machine and gets ignored.
func plural(count int, one, many string) string {
	if count == 1 {
		return "1 " + one
	}
	return strconv.Itoa(count) + " " + many
}
