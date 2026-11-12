// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/NeoTecDigital/LumberJack/core"
	"github.com/NeoTecDigital/LumberJack/extension"
	"github.com/NeoTecDigital/LumberJack/types"
)

// The write path's seams with test doubles (docs/extension-api.md §4.1, §5): a permit is taken
// before the hold and settled once after the outcome is known, with nothing held; hooks bracket
// every change in both persistences; a veto is not persisted.

type recordingPermits struct {
	server   *Server
	wants    bool
	refuse   error
	mu       sync.Mutex
	acquired []bool // whether the forest was free at Acquire
	settled  []extension.Outcome
	free     []bool // whether the forest and the writer were free at Settle
}

func (p *recordingPermits) Close(context.Context) error { return nil }

func (p *recordingPermits) Acquire(context.Context, extension.WriteOp) (extension.Permit, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.acquired = append(p.acquired, forestFree(p.server))
	if p.refuse != nil {
		return nil, p.refuse
	}
	return recordedPermit{p}, nil
}

type recordedPermit struct{ p *recordingPermits }

func (r recordedPermit) WantsRevision() bool { return r.p.wants }

func (r recordedPermit) Settle(outcome extension.Outcome) {
	r.p.mu.Lock()
	defer r.p.mu.Unlock()
	writerFree := r.p.server.stateWriter.mutex.TryLock()
	if writerFree {
		r.p.server.stateWriter.mutex.Unlock()
	}
	r.p.settled = append(r.p.settled, outcome)
	r.p.free = append(r.p.free, forestFree(r.p.server) && writerFree)
}

// forestFree reports whether nobody holds the forest, in either mode.
func forestFree(server *Server) bool {
	if !server.forestMutex.TryLock() {
		return false
	}
	server.forestMutex.Unlock()
	return true
}

func withPermits(t *testing.T, server *Server, permits *recordingPermits) {
	t.Helper()
	permits.server = server
	ext := testExtension{spec: extension.Spec{Name: "permits"}, attach: func(extension.Host) (extension.Instance, error) { return permits, nil }}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
}

func addRootChild(server *Server, name string) func() error {
	return func() error {
		node := core.NewNode(core.LeafNode, name)
		node.Parents = map[string]string{server.forest.ID: server.forest.Name}
		server.forest.Children[node.ID] = node
		return nil
	}
}

func TestPermitAcquiredBeforeHoldAndSettledAfterDurable(t *testing.T) {
	server, _ := newStockServer(t)
	permits := &recordingPermits{}
	withPermits(t, server, permits)
	commit, err := server.changeForestOp(extension.WriteOp{Key: "first"}, addRootChild(server, "first"))
	if err != nil {
		t.Fatal(err)
	}
	if len(permits.acquired) != 1 || !permits.acquired[0] || len(permits.settled) != 1 || !permits.free[0] {
		t.Fatalf("acquired %v settled %d free %v: the permit must be taken and settled with nothing held", permits.acquired, len(permits.settled), permits.free)
	}
	settled := permits.settled[0]
	if settled.State != extension.WriteDurable || settled.Commit != commit || commit.Seq != server.stateWriter.durableSeq {
		t.Fatalf("settled %+v, commit %+v, durable %d", settled, commit, server.stateWriter.durableSeq)
	}
}

func TestPermitProviderIsAtMostOne(t *testing.T) {
	server, _ := newStockServer(t)
	two := []extension.Extension{
		testExtension{spec: extension.Spec{Name: "one"}, attach: func(extension.Host) (extension.Instance, error) { return &recordingPermits{}, nil }},
		testExtension{spec: extension.Spec{Name: "two"}, attach: func(extension.Host) (extension.Instance, error) { return &recordingPermits{}, nil }},
	}
	if err := server.AttachExtensions(two); !errors.Is(err, ErrExtensionSet) {
		t.Fatalf("two permit providers were accepted: %v", err)
	}
}

func TestRefusedChangeReportsUnchangedOnlyWhenAsked(t *testing.T) {
	refusal := apiErrorf(409, "refused")
	for _, wants := range []bool{true, false} {
		server, _ := newStockServer(t)
		permits := &recordingPermits{wants: wants}
		withPermits(t, server, permits)
		_, _ = server.changeForestOp(extension.WriteOp{Key: "clean"}, func() error { return refusal })
		_, _ = server.changeForestOp(extension.WriteOp{Key: "dirty"}, func() error {
			_ = addRootChild(server, "left-behind")()
			return refusal
		})
		clean, dirty := permits.settled[0], permits.settled[1]
		if clean.State != extension.WriteRefused || dirty.State != extension.WriteRefused || !errors.Is(clean.Err, refusal) {
			t.Fatalf("wants=%v: refusals settled %+v %+v", wants, clean, dirty)
		}
		if clean.Unchanged != wants || dirty.Unchanged {
			t.Fatalf("wants=%v: unchanged %v (clean) %v (dirty)", wants, clean.Unchanged, dirty.Unchanged)
		}
	}
}

func TestFailedPersistSettlesUnknown(t *testing.T) {
	server, _ := newStockServer(t)
	permits := &recordingPermits{}
	withPermits(t, server, permits)
	server.stateWriter.write = func(stateSnapshot) error { return errors.New("the disk refused") }
	if _, err := server.changeForestOp(extension.WriteOp{Key: "lost"}, addRootChild(server, "lost")); err == nil {
		t.Fatal("a write the disk refused was acknowledged")
	}
	if outcome := permits.settled[0]; outcome.State != extension.WriteUnknown || outcome.Err == nil || !permits.free[0] {
		t.Fatalf("a failed persist settled %+v (free %v)", outcome, permits.free[0])
	}
}

func TestProviderErrorIsNoEffect(t *testing.T) {
	server, _ := newStockServer(t)
	permits := &recordingPermits{refuse: errors.New("fenced")}
	withPermits(t, server, permits)
	called := false
	if _, err := server.changeForestOp(extension.WriteOp{Key: "fenced"}, func() error { called = true; return nil }); err == nil || called {
		t.Fatalf("a refused permit ran the change (%v) or answered %v", called, err)
	}
	if len(permits.settled) != 0 {
		t.Fatal("a permit that was never granted was settled")
	}
}

// vetoHook restores a metadata key it protects and vetoes any change that touched it.
type vetoHook struct {
	calls int
}

func (h *vetoHook) Close(context.Context) error { return nil }

func (h *vetoHook) BeforeChangeLocked(tx extension.Tx, _ extension.WriteOp) (extension.After, error) {
	h.calls++
	root := tx.Root()
	held, had := root.Metadata["protected"]
	return func(tx extension.Tx, _ error) error {
		if root.Metadata["protected"] == held {
			return nil
		}
		if had {
			root.Metadata["protected"] = held
		} else {
			delete(root.Metadata, "protected")
		}
		return errors.New("protected is not yours to change")
	}, nil
}

func withHook(t *testing.T, server *Server, hook *vetoHook) {
	t.Helper()
	ext := testExtension{spec: extension.Spec{Name: "hook"}, attach: func(extension.Host) (extension.Instance, error) { return hook, nil }}
	if err := server.AttachExtensions([]extension.Extension{ext}); err != nil {
		t.Fatal(err)
	}
}

func TestHookVetoRestoresAndIsNotPersisted(t *testing.T) {
	server, _ := newStockServer(t)
	hook := &vetoHook{}
	withHook(t, server, hook)
	before, err := os.ReadFile(server.statePath())
	if err != nil {
		t.Fatal(err)
	}
	err = server.changeForest(func() error {
		if server.forest.Metadata == nil {
			server.forest.Metadata = map[string]interface{}{}
		}
		server.forest.Metadata["protected"] = "changed"
		return nil
	})
	var status *apiError
	if !asAPIError(err, &status) || status.status != 403 {
		t.Fatalf("a vetoed change answered %v", err)
	}
	if _, present := server.forest.Metadata["protected"]; present {
		t.Fatal("the hook did not restore what it protects")
	}
	after, err := os.ReadFile(server.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a vetoed change was persisted")
	}
}

func TestHooksRunInBothPersistences(t *testing.T) {
	inEachMode(t, func(t *testing.T, config types.ServerConfig) {
		server := newServerWith(t, config)
		hook := &vetoHook{}
		withHook(t, server, hook)
		for _, name := range []string{"one", "two"} {
			if err := server.changeForest(addRootChild(server, name)); err != nil {
				t.Fatal(err)
			}
		}
		if hook.calls != 2 {
			t.Fatalf("%s: the hook ran %d times for two writes", config.Persistence.Mode, hook.calls)
		}
	})
}
