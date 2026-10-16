// Written by Richard Christopher, Copyright 2026 Richard Christopher

package graph

import (
	"strings"
	"sync"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/core"
)

// Engine is the command engine over one forest, with the decoded graph KEPT between commands.
//
// Decoding every record out of the forest, copying the result and checking all of it was the cost
// of each command, and it grew with the graph rather than with the command. The forest is still
// the only store: the engine holds what it decoded from it, advances that copy with each command
// it writes, and decodes again only when the graph root it decoded is no longer the one in the
// forest, or is no longer at the revision the engine left it at. Nothing but the engine writes
// beneath the graph root — the generic routes refuse to — so between commands the two agree.
//
// The caller holds the forest: exclusively for Commit, at least shared for Snapshot. The engine's
// own lock is only what lets two shared holders ask it to decode at the same moment.
type Engine struct {
	mutex sync.Mutex
	// behind reports that the forest in memory is ahead of its state file: the last flush failed
	// and none has succeeded since. It is nil for a forest nothing persists.
	behind func() bool
	// loaded says the three fields below describe root; a nil root is a graph not yet created.
	loaded bool
	root   *core.Node
	state  *State
	lay    *layout
	// unsound is why the decoded graph cannot take a command: what a whole-graph check found when
	// it was decoded. Reads still answer what is stored.
	unsound error
}

// NewEngine builds an engine. behind may be nil.
func NewEngine(behind func() bool) *Engine {
	return &Engine{behind: behind}
}

// open makes the kept state describe the graph under forest. The caller holds e.mutex.
func (e *Engine) open(forest *core.Node) error {
	root := Root(forest)
	if e.loaded && root == e.root && (root == nil || metaRevision(root.Metadata) == e.state.Revision) {
		return nil
	}
	state, lay, err := load(root)
	if err != nil {
		e.loaded = false
		return err
	}
	e.loaded, e.root, e.state, e.lay = true, root, state, lay
	e.unsound = validateState(state)
	return nil
}

// Snapshot is the whole graph under forest. The caller holds the forest for reading.
func (e *Engine) Snapshot(forest *core.Node) (Snapshot, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if err := e.open(forest); err != nil {
		return Snapshot{}, err
	}
	return e.state.snapshot(), nil
}

// Commit validates one command against the graph under forest and only then writes it.
//
// Validation runs on a DRAFT laid over the kept state, so a command that is refused — for any
// reason — has touched neither the forest nor that state. The write phase that follows cannot
// fail. The caller holds the forest exclusively and persists after this returns; nothing here
// touches the disk.
//
// A command whose id has a receipt is REPLAYED whatever else is true, because a retry is how a
// caller that was answered 5xx finds out what happened. A new command is refused while the forest
// is ahead of its file: accepting it would stack a second unacknowledged change on the first.
func (e *Engine) Commit(forest *core.Node, cmd Command, userID string, now time.Time) (Result, error) {
	result, _, err := e.CommitTracked(forest, cmd, userID, now)
	return result, err
}

// CommitTracked is Commit that also reports every node the command wrote, so the caller can
// persist the change rather than the store. A replayed command wrote nothing and reports an empty
// set; a refused one reports nil.
func (e *Engine) CommitTracked(forest *core.Node, cmd Command, userID string, now time.Time) (Result, *Touched, error) {
	ops, err := prepare(&cmd)
	if err != nil {
		return Result{}, nil, err
	}
	digest := commandDigest(cmd)
	if strings.TrimSpace(cmd.Actor) == "" {
		cmd.Actor = userID
	}
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if err := e.open(forest); err != nil {
		return Result{}, nil, err
	}
	if receipt, found, err := e.lay.receipt(cmd.ID); err != nil || found {
		result, err := replay(receipt, cmd, digest, err)
		if err != nil {
			return Result{}, nil, err
		}
		return result, newTouched(), nil
	}
	if e.behind != nil && e.behind() {
		return Result{}, nil, ErrUnavailable
	}
	if e.unsound != nil {
		return Result{}, nil, e.unsound
	}
	st, err := stage(e.state, ops, cmd.Expected)
	if err != nil {
		return Result{}, nil, err
	}
	touched := newTouched()
	if e.root == nil {
		touched.edges(forest)
		e.root = newRoot(forest, userID, now)
		touched.created(e.root)
		e.lay.root = e.root
	}
	result := Result{CommandID: cmd.ID, Revision: st.draft.revision, Changes: st.changes}
	w := &writer{lay: e.lay, state: e.state, draft: st.draft, cmd: cmd, digest: digest, userID: userID, now: now, touched: touched}
	w.write(result)
	return result, touched, nil
}

// replay answers a command whose id has been seen: the stored result if the payload is the same,
// a conflict if it is not.
func replay(receipt Receipt, cmd Command, digest string, err error) (Result, error) {
	if err != nil {
		return Result{}, err
	}
	if receipt.Fingerprint != cmd.Fingerprint || receipt.PayloadDigest != digest {
		return Result{}, conflictf(commandsCollection, cmd.ID, "was already used with different content")
	}
	out := receipt.Result
	out.Replayed = true
	return out, nil
}
