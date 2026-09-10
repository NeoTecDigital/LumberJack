package internal

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/NeoTecDigital/LumberJack/internal/core"
	"github.com/NeoTecDigital/LumberJack/types"
)

// The state file holds the WHOLE forest, and the forest holds every user's bcrypt hash. It is
// readable by its owner and nobody else; it used to be written 0644, which handed every local
// account on the box the password hash of every account on the server.
//
// The directory it sits in is types.DataDirMode, which is where every entrypoint gets it from too.
const stateFileMode os.FileMode = 0600

// loadFromFile loads the forest data from the file.
//
// It reads BOTH shapes. The flat node table this program now writes is recognised by the banner in
// front of its hash; anything without that banner is a file from a build that wrote the forest as
// nested JSON, and it is read as one. See state_codec.go for why the sniff cannot live inside the
// document.
func (server *Server) loadFromFile(filename string) error {
	server.logger.Enter("loadFromFile")
	defer server.logger.Exit("loadFromFile")

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	forest, err := server.readState(file)
	if err != nil {
		return err
	}

	// EVERY ENTRY GETS AN IDENTITY BEFORE THE FOREST IS SERVED. A file written before Entry.ID
	// existed carries entries with none, and an entry with no id is one DELETE /entries/{id} can
	// never name. The ids are DERIVED from the position the file already records, so they are the
	// same on every load of that file rather than fresh on every start, and the ordinary persist
	// carries them to disk at the first mutation. See core/entry_identity.go.
	if named := core.BackfillEntryIDs(forest); named > 0 {
		server.logger.Info("Named %d entries that were written before entries had ids", named)
	}

	server.forest = forest
	// The forest is NOT logged. It carries its users, and its users carry bcrypt hashes; Debug is
	// ungated and the log file it writes to is the one GET /logs serves.
	server.logger.Debug("Loaded forest with %d users and %d children", len(server.forest.Users), len(server.forest.Children))
	return nil
}

// readState reads whichever shape the file is in and answers the forest it holds.
func (server *Server) readState(file *os.File) (*core.Node, error) {
	flat, err := hasStateMagic(file)
	if err != nil {
		return nil, err
	}

	data, err := server.readSealedPayload(file)
	if err != nil {
		return nil, err
	}

	if flat {
		forest, err := decodeState(data)
		if err != nil {
			server.logger.Failure("Failed to read the node table: %v", err)
			return nil, fmt.Errorf("error reading the node table: %v", err)
		}
		return forest, nil
	}

	return server.readNestedState(data)
}

// readNestedState reads a file written before the node table existed, and REJOINS it.
//
// Such a file writes a node once per path to it, so a node with two parents comes back as two
// objects carrying one id — see core.Canonicalize. The rejoin is exact because every occurrence of
// one id in such a file is a serialization of the same object.
func (server *Server) readNestedState(data []byte) (*core.Node, error) {
	var loadedForest core.Node
	if err := json.Unmarshal(data, &loadedForest); err != nil {
		server.logger.Failure("Failed to unmarshal data: %v", err)
		return nil, fmt.Errorf("error validating data: %v", err)
	}

	if forks := core.Canonicalize(&loadedForest); forks > 0 {
		server.logger.Info("Rejoined %d duplicated occurrences of shared nodes while loading the state file", forks)
	}
	return &loadedForest, nil
}

// hasStateMagic reports whether the file begins with the banner, leaving the reader positioned
// after it when it does and back at the start when it does not.
//
// A file SHORTER than the banner is an old file, not a broken one: the old shape's first bytes are
// a 32-byte hash and a gzip stream, and the smallest of those is well under this length.
func hasStateMagic(file *os.File) (bool, error) {
	banner := make([]byte, len(stateMagic))
	_, err := io.ReadFull(file, banner)
	switch {
	case err == nil && string(banner) == stateMagic:
		return true, nil
	case err == nil, err == io.EOF, err == io.ErrUnexpectedEOF:
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
		return false, nil
	default:
		return false, err
	}
}

// readSealedPayload reads the sha256 header and the compressed document behind it, and refuses
// anything the header does not vouch for.
func (server *Server) readSealedPayload(reader io.Reader) ([]byte, error) {
	// io.ReadFull, not Read: Read is allowed to return fewer bytes than the buffer holds without
	// erring, and a short read here leaves the rest of the hash zeroed — which fails the integrity
	// check further down as if the database were corrupt.
	hash := make([]byte, sha256.Size)
	if _, err := io.ReadFull(reader, hash); err != nil {
		return nil, err
	}

	data, err := server.loadCompressedData(reader)
	if err != nil {
		return nil, fmt.Errorf("error loading compressed data: %v", err)
	}

	if err := server.validatePayload(data, hash); err != nil {
		return nil, fmt.Errorf("error validating data: %v", err)
	}
	return data, nil
}

// TODO: Encrypt this
// persistState serializes the forest and makes it durable. It took a `data interface{}` that it
// never looked at — callers passed a node or the forest and got the forest either way.
//
// It takes the exclusive hold ITSELF, for the encode only, and lets go of it before the disk is
// touched. Nothing may call it while already holding the forest: that is what put an fsync inside
// the exclusive hold and stalled every other request behind it. Routes reach the disk through
// changeForest, which encodes under the hold and commits outside it; this shape is for the places
// that are not serving yet, and for tests.
func (server *Server) persistState(filename string) error {
	server.logger.Enter("persistState")
	defer server.logger.Exit("persistState")

	snapshot, err := server.snapshotForest(filename)
	if err != nil {
		return err
	}
	return server.commitState(snapshot)
}

// snapshotForest takes the exclusive hold and answers a serialization of the forest under it.
func (server *Server) snapshotForest(filename string) (stateSnapshot, error) {
	server.forestMutex.Lock()
	defer server.forestMutex.Unlock()

	return server.encodeStateLocked(filename)
}

// encodeStateLocked serializes the WHOLE forest and answers the snapshot that has to reach the disk
// before the change in it may be acknowledged.
//
// THE CALLER MUST HOLD server.forestMutex EXCLUSIVELY. That is what the name says, and it is not a
// nicety: this marshals the entire object graph, so a mutation running beside it is an
// unsynchronized map read against a concurrent map write.
//
// NO DISK IS TOUCHED HERE. The bytes this answers share nothing with the forest, which is what
// lets the write and the fsyncs behind it happen with the hold released — see state_writer.go. The
// sequence number is assigned here, inside the same critical section as the encode, so that
// sequence order is the order the forest actually passed through these states.
func (server *Server) encodeStateLocked(filename string) (stateSnapshot, error) {
	jsonData, err := encodeState(server.forest)
	if err != nil {
		server.logger.Failure("Failed to marshal forest: %v", err)
		return stateSnapshot{}, err
	}

	hash := sha256.New()
	hash.Write(jsonData)
	newHash := hash.Sum(nil)

	server.stateSeq++
	// lastHash is the cache's invalidation token: the hash of the newest state the forest has
	// been in, not of the file. The read cache is a view of the forest in memory, so the token
	// that invalidates it has to move when the forest does, not when the disk catches up.
	server.lastHash = newHash

	return stateSnapshot{seq: server.stateSeq, hash: newHash, data: jsonData, path: filename}, nil
}

// commitState makes a snapshot durable and MUST be called with no hold on the forest.
//
// It answers only once the bytes are on the disk, so a 200 behind it still means the change is in
// the state file and not merely in memory.
func (server *Server) commitState(snapshot stateSnapshot) error {
	server.logger.Enter("commitState")
	defer server.logger.Exit("commitState")

	if err := server.stateWriter.commit(snapshot); err != nil {
		return err
	}

	server.logger.Debug("Saved changes to file: %s", snapshot.path)
	return nil
}

// publishSnapshot is the writer's disk side: the durable publish of one serialized forest.
func (server *Server) publishSnapshot(snapshot stateSnapshot) error {
	return server.publishState(snapshot.path, snapshot.hash, snapshot.data)
}

// publishState writes the serialized forest and makes it the state file, durably.
//
// A temporary file that is renamed, and BOTH are flushed: os.Rename is atomic with respect to the
// directory entry and says nothing about the bytes behind it or about the entry itself surviving a
// power loss. This function's answer is what a handler turns into 200.
func (server *Server) publishState(filename string, newHash, jsonData []byte) error {
	// The directory is ensured at every write, not just the first: it holds this file, and this
	// file holds the hashes. A relative name with no directory part is left alone — chmodding the
	// working directory is not this function's business.
	if dir := filepath.Dir(filename); dir != "" && dir != "." {
		if err := types.EnsureDir(dir, types.DataDirMode); err != nil {
			server.logger.Failure("Failed to prepare the state directory: %v", err)
			return err
		}
	}

	tmpFile := filename + ".tmp"
	if err := server.writeStateTempFile(tmpFile, newHash, jsonData); err != nil {
		os.Remove(tmpFile)
		return err
	}

	if err := os.Rename(tmpFile, filename); err != nil {
		os.Remove(tmpFile)
		server.logger.Failure("Failed to rename temporary file: %v", err)
		return err
	}

	if err := syncDir(filepath.Dir(filename)); err != nil {
		server.logger.Failure("Failed to flush the state directory: %v", err)
		return err
	}
	return nil
}

// stateFileExists reports whether the state file is still there to be skipped.
func stateFileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

// syncDir flushes a directory entry, which is what makes a rename survive a crash.
//
// A directory with no name — the relative-path case statePath still allows — is the process's own
// working directory, and is synced as such.
func syncDir(dir string) error {
	if dir == "" {
		dir = "."
	}

	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()

	return handle.Sync()
}

// writeStateTempFile fills the temporary file that os.Rename will turn into the state file. The
// caller removes it if this reports an error, so nothing half-written is left behind under a name
// that outlives the attempt.
//
// The temporary file is created at the SAME mode as the state file it becomes. os.Create opens
// 0666&^umask — 0644 on a stock system — and os.Rename preserves the mode of the source inode, so a
// 0644 temp file leaks exactly as widely as a 0644 state file, for the whole window it exists and
// forever afterwards.
func (server *Server) writeStateTempFile(path string, hash, jsonData []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, stateFileMode)
	if err != nil {
		server.logger.Failure("Failed to create temporary file: %v", err)
		return err
	}
	defer file.Close()

	// An EXISTING temp file is not re-permissioned by O_CREATE, and neither is a state file written
	// by an older build. Both are forced back to the intended mode.
	if err := file.Chmod(stateFileMode); err != nil {
		server.logger.Failure("Failed to set permissions on temporary file: %v", err)
		return err
	}

	// The banner goes in FRONT of the hash, which is the one place a build that predates this
	// format cannot ignore it: that build reads the first 32 bytes as the hash and opens a gzip
	// stream at offset 32, so it fails on the gzip header rather than reading a document it does
	// not understand and rewriting the file without the parts it dropped. See state_codec.go.
	if _, err := file.WriteString(stateMagic); err != nil {
		server.logger.Failure("Failed to write the state banner to temporary file: %v", err)
		return err
	}

	if _, err := file.Write(hash); err != nil {
		server.logger.Failure("Failed to write hash to temporary file: %v", err)
		return err
	}

	gzipWriter := gzip.NewWriter(file)
	if _, err := gzipWriter.Write(jsonData); err != nil {
		server.logger.Failure("Failed to write compressed data to temporary file: %v", err)
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		server.logger.Failure("Failed to close gzip writer: %v", err)
		return err
	}

	// FLUSHED before the rename that publishes it. os.Rename is atomic with respect to the
	// directory entry, not with respect to the contents behind it: renaming a file whose bytes are
	// still in the page cache publishes a name that can come back truncated, and the hash check on
	// load would then reject the whole database.
	if err := file.Sync(); err != nil {
		server.logger.Failure("Failed to flush the temporary file: %v", err)
		return err
	}

	return nil
}

// maxDecompressedState bounds what a gzip'd state file may expand to in memory. A gzip stream can
// decompress to arbitrarily more than it costs to store or send, so an unbounded read is a
// decompression bomb — a few kilobytes on disk becoming gigabytes of resident memory. This ceiling
// is generous for any realistic forest and finite for a hostile one; a state file that legitimately
// exceeds it is the signal to make this configurable, not to drop the bound.
const maxDecompressedState = 1 << 30 // 1 GiB

// LoadCompressedData loads and validates gzipped JSON data from a reader, bounded so a decompression
// bomb cannot exhaust memory.
func (server *Server) loadCompressedData(reader io.Reader) ([]byte, error) {
	server.logger.Enter("loadCompressedData")
	defer server.logger.Exit("loadCompressedData")

	data, err := readCappedGzip(reader, maxDecompressedState)
	if err != nil {
		server.logger.Failure("Failed to read compressed state: %v", err)
		return nil, err
	}
	return data, nil
}

// readCappedGzip decompresses a gzip stream to completion but refuses to exceed limit bytes. It reads
// ONE byte past the ceiling so an over-limit stream is detected and rejected, rather than silently
// truncated into a shorter document — which would then fail its hash check for the wrong reason,
// reporting corruption where the real fault was size.
func readCappedGzip(reader io.Reader, limit int64) ([]byte, error) {
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	data, err := io.ReadAll(io.LimitReader(gzipReader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("decompressed state exceeds the %d-byte limit", limit)
	}
	return data, nil
}

// validatePayload refuses a document the hash in front of it does not vouch for.
func (server *Server) validatePayload(data []byte, hash []byte) error {
	server.logger.Enter("validatePayload")
	defer server.logger.Exit("validatePayload")

	dataHash := sha256.New()
	dataHash.Write(data)
	if !compareHashes(hash, dataHash.Sum(nil)) {
		server.logger.Failure("Data hash mismatch, file may be corrupted")
		return fmt.Errorf("data hash mismatch, file may be corrupted")
	}

	server.lastHash = hash
	// The file this hash came out of IS the state file, so the writer may skip a first persist
	// that would rewrite it byte for byte — which is what the skip did before it moved.
	server.stateWriter.markDurable(hash)
	// The payload is NOT logged: it is the forest, and the forest carries password hashes.
	server.logger.Debug("Validated %d bytes of state", len(data))
	return nil
}
