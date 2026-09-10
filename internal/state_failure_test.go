// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
// Non-commercial use only; see LICENSE.

// The state file's failure paths — the ones the happy-path suite never walks.
//
// file.go carries eleven distinct error returns across the write and the read, and not one of them
// was exercised: every test that touched the disk did so on a directory it had just been given and
// a file it had just written. So "the write reports its failures" and "a corrupt file is refused"
// were claims with no evidence, on the one component whose whole job is to not lose the forest.
//
// The injections here are all EXTERNAL — a directory the process may not write, a path already
// occupied by a directory, bytes deliberately wrong. Nothing here reaches into the writer to make it
// fail; each is a condition a deployment genuinely produces (a full or read-only volume, a
// half-restored backup, a truncated copy).
package internal

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// requireUnprivileged skips a test whose injection is a permission the superuser ignores.
func requireUnprivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: a mode-based refusal cannot be provoked")
	}
}

// sealedState builds the bytes of a state file: the banner, a sha256 header, and a gzip stream. The
// hash is a parameter so a caller can write one that does NOT vouch for the payload.
func sealedState(t *testing.T, payload, hash []byte) []byte {
	t.Helper()
	var file bytes.Buffer
	file.WriteString(stateMagic)
	file.Write(hash)

	writer := gzip.NewWriter(&file)
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return file.Bytes()
}

// hashOf is the seal a well-formed state file carries.
func hashOf(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return sum[:]
}

// loaderOver builds a core-only server pointed at a directory, without loading anything, so a test
// can hand readState and loadFromFile whatever bytes it likes.
func loaderOver(t *testing.T, dir string) *Server {
	t.Helper()
	config := coreConfig()
	config.Process.DatabasePath = dir
	config.Process.Name = "state"
	server := newServerCore(config)
	t.Cleanup(func() { server.Shutdown(context.Background()) })
	return server
}

// A state directory that cannot be created is reported, not written around. publishState ensures the
// directory at EVERY write, so a path whose parent is a regular file fails there — the first of the
// write path's error returns and the one that fires before a byte is produced.
func TestPublishStateReportsADirectoryItCannotCreate(t *testing.T) {
	requireUnprivileged(t)
	dir := t.TempDir()
	server := loaderOver(t, dir)

	// A FILE where the state file's directory should be. MkdirAll cannot make a directory under it.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("plant the blocker: %v", err)
	}

	err := server.publishState(filepath.Join(blocker, "sub", "state.dat"), hashOf(nil), []byte("{}"))
	if err == nil {
		t.Fatal("publishState answered nil for a directory it could not create; a 200 behind this " +
			"would be an acknowledgement of a write that never happened")
	}
}

// A temp file that cannot be created is reported, and publishState does not go on to rename a file
// it never wrote. writeStateTempFile's first error return, and the one a full volume produces.
//
// The injection is a DIRECTORY sitting on the temp path: os.OpenFile cannot open a directory for
// writing, so the create fails whatever the state directory's mode is. A read-only state directory
// would now hold against a write too — see TestPersistLeavesTheStateDirectoryModeAlone — but a
// directory on the temp path is the cleaner, mode-independent injection.
func TestWriteStateTempFileReportsACreateFailure(t *testing.T) {
	dir := t.TempDir()
	server := loaderOver(t, dir)

	statePath := filepath.Join(dir, "state.dat")
	if err := os.Mkdir(statePath+".tmp", 0o700); err != nil {
		t.Fatalf("occupy the temp path with a directory: %v", err)
	}

	if err := server.writeStateTempFile(statePath+".tmp", hashOf(nil), []byte("{}")); err == nil {
		t.Fatal("writeStateTempFile answered nil for a temp path it cannot open for writing")
	}

	if err := server.publishState(statePath, hashOf([]byte("{}")), []byte("{}")); err == nil {
		t.Fatal("publishState answered nil though the temp file could not be created")
	}
	if _, err := os.Stat(statePath); err == nil {
		t.Fatal("publishState published a state file after failing to write its temp file")
	}
}

// A persist LEAVES the state directory's mode alone. publishState creates the directory when absent
// but never re-asserts the mode of one that already exists, so an operator who narrows it keeps that
// choice — directory mode is a usable read-only switch.
//
// This REPLACES TestPersistRestoresTheStateDirectoryMode, which recorded the opposite: publishState
// called types.EnsureDir on every write, EnsureDir chmod'd the directory back to DataDirMode, and a
// directory an operator had made read-only was silently re-granted write and written into on the next
// persist.
func TestPersistLeavesTheStateDirectoryModeAlone(t *testing.T) {
	requireUnprivileged(t)
	dir := t.TempDir()
	server := loaderOver(t, dir)

	inner := filepath.Join(dir, "data")
	if err := os.Mkdir(inner, 0o500); err != nil { // read-only: the operator's choice
		t.Fatalf("make the read-only directory: %v", err)
	}
	t.Cleanup(func() { os.Chmod(inner, 0o700) })

	payload := []byte("{}")
	// The write is REFUSED by the read-only directory, not silently re-enabled by widening it.
	if err := server.publishState(filepath.Join(inner, "state.dat"), hashOf(payload), payload); err == nil {
		t.Fatal("publishState wrote into a read-only directory; it re-granted the write the operator removed")
	}

	// And the directory is STILL as the operator left it, not reset to DataDirMode.
	info, err := os.Stat(inner)
	if err != nil {
		t.Fatalf("stat the directory: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o500 {
		t.Fatalf("the state directory is %04o after a persist, want 0500 — the persist reset a mode it "+
			"must leave alone (DataDirMode is %04o)", got, types.DataDirMode.Perm())
	}
}

// A rename that cannot land is reported, and the half-written temp file is REMOVED rather than left
// under a name that outlives the attempt. A directory already occupying the state path is the
// reachable form: rename(2) will not replace a directory with a file.
func TestPublishStateReportsAFailedRenameAndLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	server := loaderOver(t, dir)

	statePath := filepath.Join(dir, "state.dat")
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatalf("occupy the state path with a directory: %v", err)
	}

	if err := server.publishState(statePath, hashOf([]byte("{}")), []byte("{}")); err == nil {
		t.Fatal("publishState answered nil though the rename onto a directory cannot have succeeded")
	}
	if _, err := os.Stat(statePath + ".tmp"); err == nil {
		t.Fatal("a failed rename left the temp file behind; the next attempt inherits a stale one")
	}
}

// A truncated state file is refused. The banner is there, so the reader commits to the flat shape,
// and then the sha256 header is short — io.ReadFull's error, which is the one readSealedPayload
// exists to make rather than reading a partly-zeroed hash and reporting corruption instead.
func TestLoadRefusesATruncatedStateFile(t *testing.T) {
	dir := t.TempDir()
	server := loaderOver(t, dir)

	path := filepath.Join(dir, "state.dat")
	truncated := append([]byte(stateMagic), bytes.Repeat([]byte{0xAB}, sha256.Size-1)...)
	if err := os.WriteFile(path, truncated, 0o600); err != nil {
		t.Fatalf("write the truncated file: %v", err)
	}

	err := server.loadFromFile(path)
	if err == nil {
		t.Fatal("a state file cut off inside its hash was loaded")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Fatalf("a truncated state file reported %v, want an unexpected EOF from the hash read", err)
	}
	if server.forest != nil && len(server.forest.Children) != 0 {
		t.Fatal("a refused load still installed a forest")
	}
}

// A state file whose payload is not a gzip stream is refused, rather than read as an empty document.
func TestLoadRefusesACorruptedCompressedPayload(t *testing.T) {
	dir := t.TempDir()
	server := loaderOver(t, dir)

	path := filepath.Join(dir, "state.dat")
	corrupt := append([]byte(stateMagic), bytes.Repeat([]byte{0x00}, sha256.Size)...)
	corrupt = append(corrupt, []byte("this is not a gzip stream")...)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatalf("write the corrupt file: %v", err)
	}

	if err := server.loadFromFile(path); err == nil {
		t.Fatal("a state file with a non-gzip payload was loaded")
	}
}

// A payload the hash in front of it does not vouch for is refused. This is the integrity check, and
// it had no test: a single flipped byte anywhere in the compressed document must stop the load.
func TestLoadRefusesAPayloadTheHashDoesNotVouchFor(t *testing.T) {
	dir := t.TempDir()
	server := loaderOver(t, dir)

	// A payload that would otherwise decode: a real forest, encoded the way the writer encodes it.
	payload, err := encodeState(core.NewForest("forest"))
	if err != nil {
		t.Fatalf("encodeState: %v", err)
	}

	path := filepath.Join(dir, "state.dat")
	// The CONTROL first: the same bytes under their true hash load cleanly, so the refusal below is
	// the hash and nothing else about the file.
	if err := os.WriteFile(path, sealedState(t, payload, hashOf(payload)), 0o600); err != nil {
		t.Fatalf("write the sealed file: %v", err)
	}
	if err := server.loadFromFile(path); err != nil {
		t.Fatalf("a correctly sealed state file was refused: %v", err)
	}

	wrong := hashOf(payload)
	wrong[0] ^= 0xFF
	if err := os.WriteFile(path, sealedState(t, payload, wrong), 0o600); err != nil {
		t.Fatalf("write the mis-sealed file: %v", err)
	}
	if err := server.loadFromFile(path); err == nil {
		t.Fatal("a state file whose hash does not match its payload was loaded")
	}
}

// A sealed payload that is not a node table is refused by the decoder rather than installed as an
// empty forest — the last of the read path's rejections.
func TestLoadRefusesASealedPayloadThatIsNotANodeTable(t *testing.T) {
	dir := t.TempDir()
	server := loaderOver(t, dir)

	payload := []byte("{\"not\": \"a node table\"")
	path := filepath.Join(dir, "state.dat")
	if err := os.WriteFile(path, sealedState(t, payload, hashOf(payload)), 0o600); err != nil {
		t.Fatalf("write the file: %v", err)
	}

	if err := server.loadFromFile(path); err == nil {
		t.Fatal("a sealed payload that is not a node table was loaded")
	}
}

// A state file that EXISTS but cannot be read is a fault, and NewCore says so instead of starting on
// a blank forest — which is the failure that matters, because a blank forest is persisted over the
// unreadable one at the first mutation and the database is gone.
//
// This is the observable form of the state file disappearing between the stat and the open: NewCore
// stats, then loads, and anything that makes the second step fail after the first succeeded must not
// be read as "there is no file here yet".
func TestNewCoreRefusesAStateFileItCannotRead(t *testing.T) {
	requireUnprivileged(t)
	dir := t.TempDir()

	config := coreConfig()
	config.Process.DatabasePath = dir
	config.Process.Name = "state"

	path := StatePath(config)
	if err := os.WriteFile(path, []byte("a state file with contents"), 0o000); err != nil {
		t.Fatalf("write the unreadable state file: %v", err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) })

	server, err := NewCore(config)
	if err == nil {
		server.Shutdown(context.Background())
		t.Fatal("NewCore started on an unreadable state file; the next persist would clobber it " +
			"with a blank forest")
	}
	if server != nil {
		t.Fatal("NewCore returned a server alongside its refusal")
	}
}

// An ABSENT file is not the same as an unreadable one, and loadFromFile must report the open rather
// than carry on with the forest it was constructed with. The control for the test above.
func TestLoadFromFileReportsAnAbsentFile(t *testing.T) {
	dir := t.TempDir()
	server := loaderOver(t, dir)

	if err := server.loadFromFile(filepath.Join(dir, "never-written.dat")); err == nil {
		t.Fatal("loadFromFile answered nil for a file that is not there")
	}
}

// A mutation whose persist cannot land is answered as a FAILURE — the whole point of holding the
// acknowledgement until the disk has it. changeForest is the path every route takes, and no test
// had ever made its commit fail.
//
// It also records what a failed persist leaves behind, which is the honest and uncomfortable part:
// the forest in memory HAS the change. The caller is correctly told 500, so it does not believe the
// write landed; but a second process reading the file and this process's own memory now disagree
// until the next successful persist rewrites the whole snapshot.
func TestChangeForestReportsAPersistThatCouldNotLand(t *testing.T) {
	dir := t.TempDir()
	server := newServerInDirs(t, dir, dir)
	defer server.Shutdown(context.Background())
	userID := adminID(t, server)

	if _, err := server.CreateNode(userID, CreateNodeRequest{Path: "work/before", Type: "leaf"}); err != nil {
		t.Fatalf("the first write must succeed: %v", err)
	}

	// The disk stops accepting writes underneath the running server: a directory on the temp path
	// every persist opens. EnsureDir cannot undo this the way it undoes a directory mode.
	tempPath := server.statePath() + ".tmp"
	if err := os.Mkdir(tempPath, 0o700); err != nil {
		t.Fatalf("occupy the temp path: %v", err)
	}

	_, err := server.CreateNode(userID, CreateNodeRequest{Path: "work/after", Type: "leaf"})
	if err == nil {
		t.Fatal("a write whose persist could not land was acknowledged; the caller believes a " +
			"change is on disk that is not")
	}
	var carried *apiError
	if !asAPIError(err, &carried) || carried.Status() != http.StatusInternalServerError {
		t.Fatalf("a failed persist answered %v, want a 500", err)
	}

	// RECORDED, not endorsed: the in-memory forest carries the change the caller was told failed.
	// The caller is correctly told 500 and does not believe the write landed — but this process's
	// memory and the file now disagree until some later persist rewrites the whole snapshot.
	if _, lookupErr := server.getNodeFromPath("work/after"); lookupErr != nil {
		t.Fatal("the in-memory forest no longer carries a change whose persist failed; this test " +
			"records that it DOES, so a change here means the divergence has been closed")
	}

	// The writer no longer vouches for the file, so the next persist WRITES rather than taking the
	// unchanged-content skip — otherwise a forest that serialises to the failed bytes would be
	// reported durable forever.
	server.stateWriter.mutex.Lock()
	stale := server.stateWriter.durableHash
	server.stateWriter.mutex.Unlock()
	if stale != nil {
		t.Fatal("a failed flush left durableHash set; the next identical persist would be skipped " +
			"and reported successful")
	}

	// The failed publish CLEANS UP after itself: nothing half-written is left under a name the next
	// attempt would inherit — here, the very directory that blocked it.
	if _, err := os.Stat(tempPath); err == nil {
		t.Fatal("the failed publish left its temp path occupied; the next attempt inherits it")
	}

	// And with the path free again a write succeeds, carrying the whole snapshot — including the
	// change that could not land — to the disk.
	if _, err := server.CreateNode(userID, CreateNodeRequest{Path: "work/recovered", Type: "leaf"}); err != nil {
		t.Fatalf("a write after the disk returned was refused: %v", err)
	}

	reloaded := reloadServer(t, dir)
	defer reloaded.Shutdown(context.Background())
	for _, path := range []string{"work/before", "work/after", "work/recovered"} {
		if _, err := reloaded.getNodeFromPath(path); err != nil {
			t.Errorf("%s did not reach the disk once the disk returned: %v", path, err)
		}
	}
}
