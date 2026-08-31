package types

import (
	"os"
	"path/filepath"
	"testing"
)

// wantDirMode is what a data or log directory is REQUIRED to be, written out as a literal.
//
// Not DataDirMode, not LogDirMode. A test that measures the mode on disk against the constant that
// produced it is a tautology — change the constant to 0755 and both sides change together, the
// suite stays green, and every install goes world-enterable. The requirement is 0700, so 0700 is
// what is asserted here, and flipping either constant fails this file.
const wantDirMode os.FileMode = 0700

// The constants themselves are the requirement, checked once, so they cannot drift silently.
func TestDirectoryModesAreOwnerOnly(t *testing.T) {
	for name, mode := range map[string]os.FileMode{"DataDirMode": DataDirMode, "LogDirMode": LogDirMode} {
		if mode != wantDirMode {
			t.Errorf("%s is %04o, want %04o", name, mode, wantDirMode)
		}
	}
	if LogFileMode != 0600 {
		t.Errorf("LogFileMode is %04o, want %04o", LogFileMode, os.FileMode(0600))
	}
}

// A directory that does not exist is created owner-only.
func TestEnsureDirCreatesAnOwnerOnlyDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")

	if err := EnsureDir(dir, DataDirMode); err != nil {
		t.Fatalf("EnsureDir reported %v", err)
	}

	if mode := statMode(t, dir); mode != wantDirMode {
		t.Errorf("%s is %04o, want %04o", dir, mode, wantDirMode)
	}
}

// A directory that ALREADY EXISTS at a wider mode is narrowed.
//
// This is the whole reason EnsureDir exists. os.MkdirAll applies its mode only to directories it
// actually creates, so every entrypoint pre-creating the data and log directories at 0755 left them
// at 0755 forever, and the 0700 in the state writer never ran on anything.
func TestEnsureDirNarrowsAnExistingWideDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")

	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to plant a world-enterable directory: %v", err)
	}
	// MkdirAll is subject to the umask, so the starting mode is forced rather than requested.
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatalf("Failed to widen %s: %v", dir, err)
	}
	if mode := statMode(t, dir); mode != 0755 {
		t.Fatalf("%s is %04o, not the 0755 this test needs to start from", dir, mode)
	}

	if err := EnsureDir(dir, DataDirMode); err != nil {
		t.Fatalf("EnsureDir reported %v", err)
	}

	if mode := statMode(t, dir); mode != wantDirMode {
		t.Errorf("%s is %04o after EnsureDir, want %04o", dir, mode, wantDirMode)
	}
}

// Only the leaf is re-permissioned. Parents may belong to other software — /var/lib is not ours to
// narrow — and creating them is as far as this goes.
func TestEnsureDirLeavesParentsAlone(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")

	if err := os.MkdirAll(parent, 0755); err != nil {
		t.Fatalf("Failed to create %s: %v", parent, err)
	}
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatalf("Failed to widen %s: %v", parent, err)
	}

	if err := EnsureDir(filepath.Join(parent, "data"), DataDirMode); err != nil {
		t.Fatalf("EnsureDir reported %v", err)
	}

	if mode := statMode(t, parent); mode != 0755 {
		t.Errorf("EnsureDir changed the parent %s to %04o", parent, mode)
	}
}

// An empty path is not a directory to make, and is not an error either.
func TestEnsureDirIgnoresAnEmptyPath(t *testing.T) {
	if err := EnsureDir("", DataDirMode); err != nil {
		t.Errorf("EnsureDir(\"\") reported %v", err)
	}
}

func statMode(t *testing.T, path string) os.FileMode {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Failed to stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}
