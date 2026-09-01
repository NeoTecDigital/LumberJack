package internal

import (
	"github.com/vaziolabs/lumberjack/internal/core"
)

// Projecting the forest for one caller: what it may see, and once each.
//
// TWO DEFECTS THIS FILE EXISTS TO CLOSE, both in the projection GET /forest and GET /forest/tree
// are built from.
//
//  1. IT ALIASED THE LIVE FOREST. `Parents: node.Parents` handed out the forest's own map, and so
//     did an entry's metadata, an event's metadata and a user's permissions. Those routes build the
//     view under the READ hold and encode it after RELEASING it, so json walked those maps while
//     POST /nodes/link was writing into them — a data race the race detector reports on both routes,
//     and one an unsynchronized map read is not required to survive. Everything a projection
//     exposes is now COPIED, so a slow client encodes a value nothing else can reach.
//
//  2. IT COUNTED PATHS, NOT NODES. The recursion carried a set of the nodes ON THE PATH it was
//     descending, which terminates a cycle but re-projects a DOUBLY-REACHABLE node on every path
//     through it. The forest is a DAG and a diamond is its whole point — one person's work
//     belonging to their tree and to an organisation's at the same time — so a ladder of n diamonds
//     made the document 2^n times the size of the forest. Thirty-seven real nodes answered 8.9 MB,
//     built UNDER THE READ LOCK with every writer stalled behind it, from about forty calls to
//     POST /nodes/link. Each node's body is now emitted ONCE and every later reach of it is a
//     REFERENCE carrying its id.
//
// And the permission filter these routes never had: handleGetForest and handleGetTree called
// neither userIDFrom nor CheckPermission, so any valid session read the entire forest. The rule is
// the one POST /query already applies — a node the caller may not read contributes nothing, but the
// walk DESCENDS THROUGH IT, because a permission granted deeper in the tree is not withdrawn by one
// that was never granted above it.

// THE WIRE SHAPE.
//
// `children` stays a nested object keyed by node id, which is what the existing clients walk. What
// is new is that a node reached a second time carries `"ref": true` and an empty body: its id, its
// name, its type and its parents, and no children, events, entries or users. The full body is
// elsewhere in the same document under the same id. A forest with no diamonds — every forest until
// POST /nodes/link existed — encodes exactly as it did before, because nothing is ever reached
// twice. A client that ignores `ref` sees a node named twice with its contents on one of them,
// which is the same thing it saw before, minus the exponential.
//
// The alternative — a flat node table with id references and no nesting — is a better shape and a
// breaking one. It is not taken here because the defect is remotely exploitable and the fix should
// not wait on every consumer.

// forestProjector projects a subgraph for one caller: it remembers who is asking, and which nodes
// have already been emitted.
type forestProjector struct {
	userID  string
	emitted map[string]bool
}

// newNodeView projects a node and everything beneath it that userID may read.
func newNodeView(node *core.Node, userID string) nodeView {
	projector := &forestProjector{userID: userID, emitted: map[string]bool{}}
	return projector.project(node)
}

// project emits a node's body the first time it is reached and a reference every time after.
//
// The caller must hold the forest for reading.
func (p *forestProjector) project(node *core.Node) nodeView {
	if node == nil {
		return nodeView{}
	}
	if p.emitted[node.ID] {
		return p.reference(node)
	}
	p.emitted[node.ID] = true

	view := p.body(node)
	for _, child := range p.visibleChildren(node) {
		view.Children[child.ID] = p.project(child)
	}
	return view
}

// body is a node's own contents, REDACTED if the caller may not read it.
//
// Only the node a request NAMES can be unreadable here — visibleChildren never yields one — and
// that node is the document's own root, which has to be present for what hangs below it to be
// reachable. A redacted root carries its identity and nothing of what it holds: not its users,
// which on the forest root is every account in the install.
func (p *forestProjector) body(node *core.Node) nodeView {
	view := p.reference(node)
	view.Reference = false
	view.Children = make(map[string]nodeView, len(node.Children))
	if !p.readable(node) {
		return view
	}

	view.Events = newEventViews(node.Events)
	view.PlannedEvents = newEventViews(node.PlannedEvents)
	view.Users = newUserViews(node.Users)
	view.Entries = newEntryViews(node.Entries)
	view.Attachments = newAttachmentViews(node.Attachments)
	view.CreatedBy, view.CreatedAt = node.CreatedBy, node.CreatedAt
	view.ModifiedBy, view.ModifiedAt = node.ModifiedBy, node.ModifiedAt
	return view
}

// reference is a node whose body is emitted elsewhere in the same document.
//
// The empty maps and slices are EMPTY rather than absent, so that a client iterating `children` or
// `users` does not have to tell a reference apart from a leaf before it can iterate either.
func (p *forestProjector) reference(node *core.Node) nodeView {
	return nodeView{
		ID:            node.ID,
		Type:          node.Type,
		Name:          node.Name,
		Reference:     true,
		Parents:       copyStringMap(node.Parents),
		Children:      map[string]nodeView{},
		Events:        map[string]eventView{},
		PlannedEvents: map[string]eventView{},
		Users:         []userView{},
		Entries:       []entryView{},
	}
}

// visibleChildren is a node's children as this caller may see them: a readable child is itself, and
// an unreadable one is REPLACED by its own nearest readable descendants.
//
// Contracting rather than pruning is what POST /query already does. A user granted read on one
// branch and nothing above it — which is the ordinary shape of a grant — would otherwise be shown
// an empty forest, because the root it starts from is not theirs to read.
//
// Ordered BY NAME, so which reach of a shared node carries the body and which carries the reference
// is the same on every request: Go randomizes map iteration, and a document whose contents move
// between two identical requests cannot be diffed or cached.
func (p *forestProjector) visibleChildren(node *core.Node) []*core.Node {
	visible := make([]*core.Node, 0, len(node.Children))
	p.collectVisible(node, map[string]bool{node.ID: true}, &visible)
	return visible
}

// collectVisible descends through the children the caller may not read, gathering the readable
// nodes below them. The seen set is per call and guards the descent against the cycles and the
// diamonds a DAG has; it is NOT the emitted set, which spans the whole document.
func (p *forestProjector) collectVisible(node *core.Node, seen map[string]bool, into *[]*core.Node) {
	for _, child := range childrenByName(node) {
		if seen[child.ID] {
			continue
		}
		seen[child.ID] = true

		if p.readable(child) {
			*into = append(*into, child)
			continue
		}
		p.collectVisible(child, seen, into)
	}
}

// readable reports whether this caller may see a node at all.
func (p *forestProjector) readable(node *core.Node) bool {
	return node.CheckPermission(p.userID, core.ReadPermission)
}

// The copies. A projection that carries a map out of the forest is a projection whose encoder races
// every writer, so nothing below here hands back anything the forest still owns.

// copyStringMap copies a map of strings, preserving the difference between absent and empty: a
// client can tell "this node has no parents" from "this document does not say".
func copyStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}

	copied := make(map[string]string, len(values))
	for key, value := range values {
		copied[key] = value
	}
	return copied
}

// copyMetadataMap copies metadata DEEPLY, preserving absent versus empty.
//
// Deeply because metadata is arbitrary JSON: a canvas layout is an object inside the map, and a
// shallow copy would hand the nested object straight back out of the forest.
func copyMetadataMap(metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		return nil
	}

	copied := make(map[string]interface{}, len(metadata))
	for key, value := range metadata {
		copied[key] = copyValue(value)
	}
	return copied
}

// copyValue copies one decoded JSON value. Anything that is not a container is immutable and is
// itself; a container is rebuilt. JSON has no cycles, so this terminates.
func copyValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		return copyMetadataMap(typed)
	case []interface{}:
		copied := make([]interface{}, len(typed))
		for index, item := range typed {
			copied[index] = copyValue(item)
		}
		return copied
	default:
		return value
	}
}
