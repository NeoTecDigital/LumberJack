package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// The node types a client may ask for by name. The forest is branches and leaves; events live on
// leaves, so a request that does not say is asking for the thing it can track events on.
const (
	leafNodeType   = "leaf"
	branchNodeType = "branch"
)

// handleCreateNode creates the node a path names, so that a client can reach a LEAF.
//
// THIS IS THE ROUTE THE EVENT FLOW WAS MISSING. The forest is rooted on a branch, StartEvent
// refuses anything that is not a leaf, and no route created one — so on a fresh instance
// /events/start could only ever answer "cannot add event to non-leaf node" and /events/append
// could only ever answer "event not found". A client now creates the leaf it is going to track on.
//
// EVERY MISSING ANCESTOR IS CREATED AS A BRANCH, because that is the only thing an intermediate
// segment of a path can be: it has a child. Only the last segment takes the requested type.
//
// It is IDEMPOTENT, so a client that starts twice against the same path does not have to
// distinguish "I made it" from "it was already there".
func (server *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	server.logger.Enter("CreateNode")
	defer server.logger.Exit("CreateNode")

	userID, ok := userIDFrom(r)
	if !ok {
		http.Error(w, "No user in session", http.StatusUnauthorized)
		return
	}

	path, nodeType, err := decodeNodeRequest(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	// Creating the path and persisting it are ONE exclusive hold on the forest: createNodePath
	// walks and writes the Children map of every node on the path, which is the same map the
	// persist serializes.
	//
	// WHAT THE ANSWER SAYS IS READ INSIDE THE HOLD. A *core.Node carried out of changeForest is a
	// node another request may already be writing: AddBranchChild promotes a childless leaf to a
	// branch, and promoteToBranch writes Type under a DIFFERENT request's hold. Two ordinary
	// POST /nodes — one making `work/n` and one making `work/n/c` — were therefore a write to Type
	// against this handler's read of it.
	created, err := server.createNodeUnderHold(path, nodeType, userID)
	if err != nil {
		writeAPIError(w, err)
		return
	}

	canonical := server.canonicalPath(path)
	server.publish(mutation(mutationNodeCreated, canonical))
	writeCreatedNode(w, created, canonical)
	server.logger.Success("Created node at %s", path)
}

// createNodeUnderHold makes the path and reports what the answer needs to say about it.
func (server *Server) createNodeUnderHold(path string, nodeType core.NodeType, userID string) (nodeAnswer, error) {
	var created nodeAnswer

	err := server.changeForest(func() error {
		node, err := server.createNodePath(path, nodeType, userID)
		if err != nil {
			server.logger.Failure("Failed to create node %s: %v", path, err)
			return apiErrorf(statusForNodeError(err), "%v", err)
		}
		created = nodeAnswer{id: node.ID, name: node.Name, nodeType: node.Type}
		return nil
	})
	return created, err
}

// writeCreatedNode answers with where the thing the caller just made lives.
//
// The node itself is NOT the answer: it carries its users, and its users carry password hashes.
func writeCreatedNode(w http.ResponseWriter, created nodeAnswer, canonical string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":   created.id,
		"name": created.name,
		"path": canonical,
		"type": nodeTypeName(created.nodeType),
	})
}

// nodeAnswer is everything the response says about the node that was made, COPIED out of it while
// the forest is still held. It exists so that nothing below reaches back into a live node.
type nodeAnswer struct {
	id       string
	name     string
	nodeType core.NodeType
}

// decodeNodeRequest reads the path a client wants and the type it wants there.
func decodeNodeRequest(r *http.Request) (string, core.NodeType, error) {
	var request struct {
		Path string `json:"path"`
		Type string `json:"type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return "", core.LeafNode, apiErrorf(http.StatusBadRequest, "%v", err)
	}

	nodeType, err := nodeTypeOf(request.Type)
	if err != nil {
		return "", core.LeafNode, apiErrorf(http.StatusBadRequest, "%v", err)
	}
	return request.Path, nodeType, nil
}

// createNodePath walks the path from the root, creating what is not there yet.
//
// The write permission is checked on EACH PARENT rather than once at the root: a user who may
// extend one branch has not thereby been given the rest of the forest.
func (server *Server) createNodePath(path string, nodeType core.NodeType, userID string) (*core.Node, error) {
	// Either form of the path, reduced to the segments below the root: a client that round-trips a
	// canonical `forest/work/x` back into this route must not create a node literally named
	// `forest` under the root. See node_path.go.
	parts := server.segmentsFrom(path)
	if len(parts) == 0 {
		return nil, fmt.Errorf("path is required: the root already exists")
	}

	parent := server.forest

	for i, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("empty segment in path: %s", path)
		}

		if !parent.CheckPermission(userID, core.WritePermission) {
			return nil, fmt.Errorf("insufficient permissions on %s", parent.Name)
		}

		// Only the last segment is what the client asked for; an ancestor holds a child, which
		// makes it a branch whatever the request said — and an empty leaf already sitting on an
		// ancestor segment is promoted to one rather than blocking the path.
		var child *core.Node
		var err error
		if i == len(parts)-1 {
			child, err = parent.AddChildNode(part, nodeType, userID)
		} else {
			child, err = parent.AddBranchChild(part, userID)
		}
		if err != nil {
			return nil, err
		}
		parent = child
	}

	return parent, nil
}

// nodeTypeOf reads the type a request asked for. An unstated type is a leaf: events need one, and
// creating a path in order to track something on it is what this route is for.
func nodeTypeOf(name string) (core.NodeType, error) {
	switch name {
	case "", leafNodeType:
		return core.LeafNode, nil
	case branchNodeType:
		return core.BranchNode, nil
	default:
		return core.LeafNode, fmt.Errorf("unknown node type %q: use %q or %q", name, leafNodeType, branchNodeType)
	}
}

// nodeTypeName is the name a client used to ask for the type, for the answer it gets back.
func nodeTypeName(nodeType core.NodeType) string {
	if nodeType == core.BranchNode {
		return branchNodeType
	}
	return leafNodeType
}

// statusForNodeError separates "you may not" and "that cannot be" from a server fault, so a client
// can tell a mistake it made from one the service made.
func statusForNodeError(err error) int {
	switch {
	case strings.Contains(err.Error(), "insufficient permissions"):
		return http.StatusForbidden
	case strings.Contains(err.Error(), "already exists"):
		return http.StatusConflict
	// A leaf that records something cannot become a branch. That is a conflict with what is already
	// there, not a malformed request.
	case strings.Contains(err.Error(), "cannot add a child to leaf node"):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}
