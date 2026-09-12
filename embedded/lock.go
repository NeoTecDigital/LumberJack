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
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/NeoTecDigital/LumberJack/internal"
	"github.com/NeoTecDigital/LumberJack/types"
)

// ErrLocked is what Open answers when another holder — in practice another process — has the path's
// sidecar flocked RIGHT NOW. It is a fact about the boundary, not a fault: the caller retries or
// backs off, it does not treat it as corruption. It is the one refusal that clears on its own, which
// is why it is kept apart from ErrUnguarded below.
var ErrLocked = errors.New("lumberjack: state file is locked by another runtime")

// ErrUnguarded is what Open answers when a state file exists and its lock sidecar does NOT. It is
// PERMANENT and operator-actionable — no amount of retrying clears it — which is why it is not
// ErrLocked: a caller that reads a missing sidecar as a held lock backs off forever on a condition
// only a human can settle. Three things leave a forest like this: it was written before the writer
// minted a sidecar with every state file (internal/file.go), it was restored from a backup that did
// not carry its `<state>.lock`, or the sidecar was DELETED — possibly while another process still
// held it. From the filesystem the innocent cases cannot be told from the last one, so Open refuses
// all three and leaves the decision to Adopt.
var ErrUnguarded = errors.New("lumberjack: the state file has no lock sidecar; Adopt it to open")

// ErrGuarded is what Adopt answers when the sidecar is already there — nothing to adopt. It is an
// error rather than a no-op so that Adopt is ONE-SHOT: a caller that leaves an adopt in front of
// every open is told so on the very next start, instead of carrying a silent re-mint that would
// reopen the deleted-sidecar hole ErrUnguarded exists to close.
var ErrGuarded = errors.New("lumberjack: the state file already has its lock sidecar; nothing to adopt")

// adoptLog is where Adopt records the act. Standard error, so it lands wherever the host's does — the
// FFI's panic guard reports there too — and a variable so a test can read the line it writes.
var adoptLog io.Writer = os.Stderr

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
// change, or a backup restored without its `<state>.lock` — all of which are refused ErrUnguarded,
// distinct from ErrLocked because retrying cannot clear it, and the remedy for the innocent ones is
// Adopt.
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
			"file; refusing to mint a rival that would not contend with a live holder — Adopt the "+
			"forest to reopen: %w", lockPath, ErrUnguarded)
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

// Adopt mints the lock sidecar beside a state file that has none, so a forest that predates the
// sidecar — or one restored without it — can be opened. It is the ONE route past ErrUnguarded, and it
// is deliberately a separate, explicit call rather than a flag on Open: the caller is asserting that
// no other process holds the file, a fact this layer cannot check from the filesystem (a
// deleted-while-held sidecar leaves its holder flocking an unlinked inode that nothing can find).
//
// It is ONE-SHOT: ErrGuarded when the sidecar is already there, and os.ErrNotExist when there is no
// state file to adopt — a path with no state file mints its own sidecar on Open and needs nothing.
// One-shot is per missing-sidecar EPISODE, not per forest: delete the sidecar again while a holder is
// live and Adopt succeeds again, blind to the holder, and the next Open is a rival. The guard is that
// Open never adopts and that a caller adopts only on a human's decision — not this refusal, which
// protects an automated adopt only while the sidecar survives and only if ErrGuarded is treated as
// fatal. It writes one line to adoptLog (standard error) when it adopts, so the act is on record. A
// `touch <state>.lock` by hand is the same act; this is it with the checks.
func Adopt(config Config) error {
	config, err := canonicalConfig(config)
	if err != nil {
		return err
	}
	key, err := canonicalPath(config)
	if err != nil {
		return err
	}
	return adoptSidecar(key)
}

// AdoptPath is Adopt over the state file a directory and base name locate, for the C ABI, which
// depends on this package alone and never names the config's internals.
func AdoptPath(databasePath, name string) error {
	return Adopt(Config{Process: types.ProcessInfo{DatabasePath: databasePath, Name: name}})
}

// adoptSidecar creates the sidecar beside an existing state file, O_EXCL so two adopters racing over
// one path mint one sidecar between them and the loser is told ErrGuarded rather than handed a rival.
func adoptSidecar(statePath string) error {
	if !stateFileBeside(statePath) {
		return fmt.Errorf("lumberjack: no state file at %q to adopt: %w", statePath, os.ErrNotExist)
	}

	lockPath := lockPathFor(statePath)
	file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("lumberjack: %q is present: %w", lockPath, ErrGuarded)
	}
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	fmt.Fprintf(adoptLog, "lumberjack: adopted %s: minted its lock sidecar %s on the caller's word "+
		"that no other process holds the file\n", statePath, lockPath)
	return nil
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
