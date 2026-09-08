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
	"os"
	"path/filepath"
	"syscall"
)

// ErrLocked is what Open answers when another holder — in practice another process — already has the
// path. It is a fact about the boundary, not a fault: the caller retries or backs off, it does not
// treat it as corruption.
var ErrLocked = errors.New("lumberjack: state file is locked by another runtime")

// lockPathFor is the sidecar that guards a state path. It sits beside the state file and is never
// renamed over, which is the whole reason the lock is taken here rather than on the state file.
func lockPathFor(statePath string) string {
	return statePath + ".lock"
}

// acquireLock opens the sidecar lock file for a state path, creating it if absent, and takes an
// exclusive non-blocking flock. LOCK_NB is what turns a second holder into ErrLocked rather than a
// wait that never ends.
func acquireLock(statePath string) (*os.File, error) {
	lockPath := lockPathFor(statePath)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o644)
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

// releaseLock drops the flock and closes the file description holding it. Closing the description
// releases the lock on its own; the explicit unlock states the intent and is harmless.
func releaseLock(file *os.File) error {
	if file == nil {
		return nil
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return file.Close()
}
