// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// Package embedded is Lumberjack as a library: the forest lifecycle with no HTTP and no session
// signing key, for a process that holds the store in-memory rather than talking to a server. The C
// ABI is built on this and imports only this, never internal, so the ABI is a serialisation of this
// API and the two cannot drift.
//
// It owns two things nothing else does. A RUNTIME is refcounted by canonical state path, so a process
// acting for fifty principals holds one forest and one writer, not fifty racing on one file. A FLOCK
// on a sidecar `<state>.lock` refuses a second process the same path — on the sidecar rather than the
// state file because persistence renames a fresh inode over the state file and a lock follows the
// inode, so a lock on the state file itself is orphaned by the very first write. See lock.go.
package embedded

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal"
)

// Runtime is one open forest: the engine, the lock that guards its file between processes, the epoch
// that numbers its in-memory sequences, and the refcount that keeps it single within this one.
//
// Its fields are set once at Open and never change except refs, which the registry mutex guards. The
// server pointer is what two handles over one path SHARE.
type Runtime struct {
	server *internal.Server
	path   string   // canonical state path — the registry key and the locked file
	lock   *os.File // the file description holding the flock, released on the last Close
	epoch  uint64   // this run's sequence numbering, so a cursor from a past run is not resumed
	refs   int      // open handles over this runtime; guarded by registryMu
	closed chan struct{}
}

// registry is the one place a path maps to its runtime, so a second Open of the same path finds the
// first rather than building a rival.
var (
	registryMu sync.Mutex
	registry   = map[string]*Runtime{}
)

// Open opens the forest a config names, for one principal, and returns a handle bound to that
// principal.
//
// A second Open of the SAME path shares the first's runtime — the principal is what differs between
// handles, not the forest. The FIRST Open of a path takes the flock before it builds anything, so a
// second process is refused (ErrLocked) before any work is done. The principal is bound here and for
// the life of the handle: an embedder acts as one identity per handle, and holds as many handles as
// it acts as identities.
func Open(config Config, principal string) (*Handle, error) {
	key, err := canonicalPath(config)
	if err != nil {
		return nil, err
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	if rt, ok := registry[key]; ok {
		rt.refs++
		return &Handle{runtime: rt, principal: principal}, nil
	}

	// The lock FIRST: a second process must be refused before this one builds a forest it would then
	// have to tear down.
	lock, err := acquireLock(key)
	if err != nil {
		return nil, err
	}

	server, err := internal.NewCore(config)
	if err != nil {
		releaseLock(lock)
		return nil, err
	}

	rt := &Runtime{
		server: server,
		path:   key,
		lock:   lock,
		epoch:  newEpoch(),
		refs:   1,
		closed: make(chan struct{}),
	}
	registry[key] = rt
	return &Handle{runtime: rt, principal: principal}, nil
}

// close drops one reference and, on the LAST one, tears the runtime down: it leaves the registry so a
// later Open builds fresh, wakes any blocked poller by closing its signal, shuts the engine down, and
// releases the flock so another process may take the path.
func (rt *Runtime) close() error {
	registryMu.Lock()
	defer registryMu.Unlock()

	if rt.refs <= 0 {
		return nil
	}
	rt.refs--
	if rt.refs > 0 {
		return nil
	}

	delete(registry, rt.path)
	close(rt.closed)
	err := rt.server.Shutdown(context.Background())
	if lockErr := releaseLock(rt.lock); err == nil {
		err = lockErr
	}
	return err
}

// canonicalPath is the registry key: the state path a config names, made absolute so the same file
// reached by two different relative paths is still one runtime.
func canonicalPath(config Config) (string, error) {
	return filepath.Abs(internal.StatePath(config))
}

// newEpoch numbers this run. It is wall-clock nanoseconds rather than a counter because a counter
// resets to the same value every process start, and the epoch exists precisely so a cursor persisted
// across a restart is not resumed against a fresh, unrelated numbering.
func newEpoch() uint64 {
	return uint64(time.Now().UnixNano())
}
