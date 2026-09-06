package internal

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// Canvas persistence: node metadata, and the DAG edges the diagram is drawn from.
//
// The canvas is an authoring surface for maps and diagrams, and its layout has to survive. The
// layout lives in Node.Metadata under a RESERVED key rather than in a parallel store, so a node and
// its placement cannot drift apart: deleting the node deletes the placement, and there is no second
// thing to keep in step. The edges are the DAG's own Parents/Children — core.AddParent could make a
// multi-parent edge since the beginning and no route ever exposed it.

// CanvasMetadataKey is where a layout lives. Reserved: it is namespaced so a caller's own metadata
// and the canvas's cannot collide, and so a client can strip it in one step.
const CanvasMetadataKey = "mindfull.canvas"

// PATCH /nodes/{path}/metadata — MERGE, not replace.
//
// Replace is the wrong verb for this. Two surfaces annotate the same node — the canvas writes a
// layout, a report writes a category — and a replace means whichever saved last silently discarded
// the other's work. A key set to null is DELETED, which is the only way a merge can ever remove
// anything.
func (server *Server) handlePatchNodeMetadata(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	path := strings.Trim(mux.Vars(r)["path"], "/")

	var patch map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var merged map[string]interface{}
	err := server.changeNode(path, userID, core.WritePermission, func(node *core.Node) error {
		mergeMetadata(node, patch, userID)
		merged = copyMetadata(node.Metadata)
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	server.publish(mutation(mutationMetadataSet, path))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"path": server.canonicalPath(path), "metadata": merged})
}

// mergeMetadata applies a patch to a node's metadata.
//
// The caller must hold the forest exclusively.
func mergeMetadata(node *core.Node, patch map[string]interface{}, userID string) {
	if node.Metadata == nil {
		node.Metadata = make(map[string]interface{}, len(patch))
	}

	for key, value := range patch {
		if value == nil {
			delete(node.Metadata, key)
			continue
		}
		node.Metadata[key] = value
	}

	node.ModifiedBy = userID
	node.ModifiedAt = time.Now()
}

// linkRequest names an edge.
type linkRequest struct {
	ParentPath string `json:"parent_path"`
	ChildPath  string `json:"child_path"`
}

// POST /nodes/link — add a parent to a node, which is what makes the structure a DAG.
//
// A node genuinely belonging to two places is the whole reason for the multi-parent model: one
// person's work belongs to their own tree and to an organisation's at the same time. That was
// creatable in core and reachable from nowhere.
func (server *Server) handleLinkNode(w http.ResponseWriter, r *http.Request) {
	server.changeEdge(w, r, mutationNodeLinked, func(parent, child *core.Node, userID string) error {
		if parent.ID == child.ID {
			return apiErrorf(http.StatusBadRequest, "a node cannot be its own parent")
		}
		if _, already := parent.Children[child.ID]; already {
			// IDEMPOTENT. A client that draws the same edge twice does not have to distinguish
			// "I made it" from "it was already there".
			return nil
		}

		// A cycle is REFUSED rather than tolerated. The traversals carry visit sets and would
		// survive one, but the state file is JSON and JSON cannot represent a cycle — the persist
		// that acknowledges the edge would recurse until the stack ran out, and the acknowledgment
		// would be for a forest that can never be written again.
		if reaches(child, parent.ID) {
			return apiErrorf(http.StatusConflict,
				"linking %s under %s would make a cycle", child.Name, parent.Name)
		}

		parent.Children[child.ID] = child
		child.AddParent(parent)
		parent.ModifiedBy, parent.ModifiedAt = userID, time.Now()
		return nil
	})
}

// DELETE /nodes/link — remove an edge.
//
// The LAST edge is refused. A node whose only parent is removed is still in memory and no longer
// reachable from the root, so it would be persisted by nothing and lost on the next start — a
// deletion nobody asked for, reported as a successful unlink.
func (server *Server) handleUnlinkNode(w http.ResponseWriter, r *http.Request) {
	server.changeEdge(w, r, mutationNodeUnlinked, func(parent, child *core.Node, userID string) error {
		if _, linked := parent.Children[child.ID]; !linked {
			return apiErrorf(http.StatusNotFound, "%s is not under %s", child.Name, parent.Name)
		}
		if len(child.Parents) <= 1 {
			return apiErrorf(http.StatusConflict,
				"%s has no other parent: unlinking it would strand it", child.Name)
		}

		delete(parent.Children, child.ID)
		delete(child.Parents, parent.ID)
		parent.ModifiedBy, parent.ModifiedAt = userID, time.Now()
		return nil
	})
}

// changeEdge is the shape both edge routes have: read the pair, confirm the caller may write BOTH
// ends, apply the change, persist — all under one exclusive hold.
//
// Both ends are checked. An edge is a change to the parent and to the child, and a caller that may
// write only one of them may not make it.
func (server *Server) changeEdge(w http.ResponseWriter, r *http.Request, announce string, change func(parent, child *core.Node, userID string) error) {
	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	var request linkRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	parentPath := strings.Trim(request.ParentPath, "/")
	childPath := strings.Trim(request.ChildPath, "/")
	if childPath == "" || parentPath == "" {
		// REFUSED, not quietly ignored. An empty path resolves to the root, so a request that named
		// neither end would have been answered 200 for an edge from the forest to itself.
		http.Error(w, "parent_path and child_path are both required", http.StatusBadRequest)
		return
	}

	err := server.changeForest(func() error {
		parent, err := server.getNodeFromPath(parentPath)
		if err != nil {
			return apiErrorf(http.StatusNotFound, "parent: %v", err)
		}
		child, err := server.getNodeFromPath(childPath)
		if err != nil {
			return apiErrorf(http.StatusNotFound, "child: %v", err)
		}

		if !parent.CheckPermission(userID, core.WritePermission) ||
			!child.CheckPermission(userID, core.WritePermission) {
			return apiErrorf(http.StatusForbidden, "Insufficient permissions")
		}
		if parent.Type != core.BranchNode {
			return apiErrorf(http.StatusConflict, "%s is a leaf and cannot hold a child", parent.Name)
		}

		return change(parent, child, userID)
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}

	server.publish(mutation(announce, childPath))
	w.WriteHeader(http.StatusOK)
}

// reaches reports whether a node is, or is above, the node with the given id.
//
// Carries a visit set: it is asked about a DAG, so the same node is reachable by several paths and
// a loop that already exists must not make the check itself run forever.
func reaches(from *core.Node, targetID string) bool {
	visited := map[string]bool{}
	queue := []*core.Node{from}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.ID == targetID {
			return true
		}
		if visited[current.ID] {
			continue
		}
		visited[current.ID] = true

		for _, child := range current.Children {
			queue = append(queue, child)
		}
	}
	return false
}
