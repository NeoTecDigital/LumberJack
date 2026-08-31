package types

import (
	"fmt"
	"os"
)

// DataDirMode is what the directory holding the state file is created as, and kept as. The state
// file is the whole forest and the forest carries every user's bcrypt hash, so the directory is
// enterable by the account that runs the service and by nobody else.
//
// LogDirMode is the same number for the same kind of reason: the log names users, paths and
// failures, and is served over HTTP by GET /logs. They are separate names because they are separate
// decisions — narrowing one is not a statement about the other.
const (
	DataDirMode os.FileMode = 0700
	LogDirMode  os.FileMode = 0700
)

// EnsureDir creates path, with any missing parents, and forces path ITSELF to mode.
//
// The chmod is the whole point. os.MkdirAll applies its mode only to directories it actually
// creates, and it is additionally subject to the process umask — so a directory that some earlier
// line, some earlier build, or some earlier release already made at 0755 keeps 0755 forever no
// matter what mode is passed here. That is exactly what happened: every entrypoint pre-created the
// data and log directories at 0755 before anything with an opinion about the mode ran, which made
// the 0700 in the state writer an unreachable no-op on every install.
//
// Only the leaf is re-permissioned. Parents may be shared with other software — /var/lib is not
// ours to narrow — and creating them is enough.
func EnsureDir(path string, mode os.FileMode) error {
	if path == "" {
		return nil
	}

	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("failed to set permissions on directory %s: %w", path, err)
	}

	return nil
}
