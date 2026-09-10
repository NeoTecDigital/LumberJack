// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The whole-path lock guarding a state file, held on a SIDECAR.
//
// There is no lock anywhere else in the tree, and persistence is a whole-forest snapshot written to a
// temp file and RENAMED over the state path (internal/file.go) — so two runtimes over one path means
// last-writer-wins and the other's work is gone, silently. Already true for two `serve` processes;
// the FFI makes it reachable by accident.
//
// The lock is on `<state>.lock`, NOT on the state file itself. A flock follows the inode, and the
// rename replaces the state file's inode on the first persist — so a lock taken on the state file is
// orphaned onto an unlinked inode the moment the runtime writes, leaving the path unguarded exactly
// once it has something to guard. The sidecar is never renamed, so the lock outlives every persist.
// It closes the race BETWEEN processes; the in-process refcount in runtime.go closes it WITHIN one,
// because a flock is per-open-file-description and a second Open in the same process would take a
// second description and deadlock against the first.
package embedded

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/NeoTecDigital/LumberJack/internal"
)

// ErrLocked is what Open answers when another holder — in practice another process — already has the
// path. It is a fact about the boundary, not a fault: the caller retries or backs off, it does not
// treat it as corruption.
var ErrLocked = errors.New("lumberjack: state file is locked by another runtime")

// lockPathFor is the sidecar that guards a state path. It sits beside the state file and is never
// renamed over, which is the whole reason the lock is taken here rather than on the state file. The
// convention is internal.StateLockPath, shared with the writer that creates the sidecar beside every
// state file (internal/file.go) so a serve-created forest still carries one for this layer to find.
func lockPathFor(statePath string) string {
	return internal.StateLockPath(statePath)
}

// acquireLock opens the sidecar lock file for a state path and takes an exclusive non-blocking
// flock. LOCK_NB is what turns a second holder into ErrLocked rather than a wait that never ends.
//
// The directory is created if it is not there; its mode is left to internal.newServerCore, which
// narrows the state directory's leaf to DataDirMode once at construction (the state file holds every
// user's bcrypt hash). Creating parents at 0755 here and narrowing only the leaf there is what keeps
// a shared parent out of it.
func acquireLock(statePath string) (*os.File, error) {
	lockPath := lockPathFor(statePath)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, err
	}

	file, err := openSidecar(lockPath, statePath)
	if err != nil {
		return nil, err
	}

	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return file, nil
}

// openSidecar opens the sidecar to be flocked. It OPENS an existing one — the ordinary reopen — and
// CREATES one only where there is no state file yet to guard.
//
// A sidecar MISSING beside an existing state file is the one case it refuses. A flock follows the
// inode, so unlinking the sidecar while a process holds it leaves that holder locking an orphaned
// inode; minting a fresh sidecar in its place would take an UNCONTENDED lock on a new inode, and the
// two processes would each believe they hold the path while writing the same state file
// last-writer-wins. Refusing to create the rival is the only defence, because from the filesystem a
// deleted-while-held sidecar is indistinguishable from one that was never there.
//
// The ordinary handover does NOT hit this: internal/file.go writes a sidecar beside every state file
// it creates, so a forest the serve path made carries one and opens normally here. What is left as
// sidecar-missing-beside-state is a sidecar that was DELETED, or a forest from before that writer
// change, or a backup restored without its `<state>.lock` — all of which are refused, and the remedy
// for the innocent ones is to recreate the empty sidecar beside the state file before opening.
func openSidecar(lockPath, statePath string) (*os.File, error) {
	file, err := os.OpenFile(lockPath, os.O_RDWR, 0o644)
	switch {
	case err == nil:
		return file, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}

	if stateFileBeside(statePath) {
		return nil, fmt.Errorf("lumberjack: the lock sidecar %q is missing beside an existing state "+
			"file; refusing to mint a rival that would not contend with a live holder — recreate it "+
			"to reopen: %w", lockPath, ErrLocked)
	}

	// A path with no state file yet may mint its first sidecar. O_EXCL so a racing opener that won
	// the create is contended with rather than silently shared, and its winner is opened instead.
	file, err = os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return os.OpenFile(lockPath, os.O_RDWR, 0o644)
	}
	if err != nil {
		return nil, err
	}
	return file, nil
}

// stateFileBeside reports whether the state file a sidecar would guard is already present. A
// directory in that spot is not a state file and is left for the open to fail on with its own error.
func stateFileBeside(statePath string) bool {
	info, err := os.Stat(statePath)
	return err == nil && !info.IsDir()
}

// releaseLock drops the flock and closes the file description holding it. Closing the description
// releases the lock on its own; the explicit unlock states the intent and is harmless.
func releaseLock(file *os.File) error {
	if file == nil {
		return nil
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return file.Close()
}
