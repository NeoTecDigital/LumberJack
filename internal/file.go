package internal

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/vaziolabs/lumberjack/internal/core"
	"github.com/vaziolabs/lumberjack/types"
)

// The state file holds the WHOLE forest, and the forest holds every user's bcrypt hash. It is
// readable by its owner and nobody else; it used to be written 0644, which handed every local
// account on the box the password hash of every account on the server.
//
// The directory it sits in is types.DataDirMode, which is where every entrypoint gets it from too.
const stateFileMode os.FileMode = 0600

// loadFromFile loads the forest data from the file.
func (server *Server) loadFromFile(filename string) error {
	server.logger.Enter("loadFromFile")
	defer server.logger.Exit("loadFromFile")

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read hash first. io.ReadFull, not Read: Read is allowed to return fewer bytes than the buffer
	// holds without erring, and a short read here leaves the rest of the hash zeroed — which fails
	// the integrity check further down as if the database were corrupt.
	hash := make([]byte, sha256.Size)
	if _, err := io.ReadFull(file, hash); err != nil {
		return err
	}

	// Read and decompress remaining data
	data, err := server.loadCompressedData(file)
	if err != nil {
		return fmt.Errorf("error loading compressed data: %v", err)
	}

	// Create a new forest and unmarshal into it
	var loadedForest core.Node
	if err := server.validateAndUnmarshal(data, hash, &loadedForest); err != nil {
		return fmt.Errorf("error validating data: %v", err)
	}

	// The DAG is REJOINED before anything can reach it. A node with two parents was written out
	// under each of them, so it comes back as two objects with one id — see core.Canonicalize.
	if forks := core.Canonicalize(&loadedForest); forks > 0 {
		server.logger.Info("Rejoined %d duplicated occurrences of shared nodes while loading the state file", forks)
	}

	// Important: Copy the loaded forest to server's forest
	server.forest = &loadedForest
	// The forest is NOT logged. It carries its users, and its users carry bcrypt hashes; Debug is
	// ungated and the log file it writes to is the one GET /logs serves.
	server.logger.Debug("Loaded forest with %d users and %d children", len(server.forest.Users), len(server.forest.Children))
	return nil
}

// TODO: Encrypt this
// persistLocked persists the WHOLE forest to the state file. It took a `data interface{}` that it
// never looked at — callers passed a node or the forest and got the forest either way.
//
// THE CALLER MUST HOLD server.forestMutex EXCLUSIVELY. That is what the name says, and it is not a
// nicety: this marshals the entire object graph, so a mutation running beside it is an
// unsynchronized map read against a concurrent map write. Routes reach it through changeForest,
// which is the only thing that takes the lock; NewServer reaches it before the server is serving.
func (server *Server) persistLocked(filename string) error {
	server.logger.Enter("persistLocked")
	defer server.logger.Exit("persistLocked")

	// Always save the entire forest state
	jsonData, err := json.Marshal(server.forest)
	if err != nil {
		server.logger.Failure("Failed to marshal forest: %v", err)
		return err
	}

	hash := sha256.New()
	hash.Write(jsonData)
	newHash := hash.Sum(nil)

	// The skip is an ACKNOWLEDGMENT that the caller's change is already on disk, so it is only
	// honest while the file it went to is still there. An install whose data directory was cleared
	// underneath it was otherwise told every write succeeded while nothing was ever written.
	if server.lastHash != nil && compareHashes(server.lastHash, newHash) && stateFileExists(filename) {
		server.logger.Debug("No changes to save")
		return nil
	}

	if err := server.publishState(filename, newHash, jsonData); err != nil {
		return err
	}

	server.lastHash = newHash
	server.logger.Debug("Saved changes to file: %s", filename)
	return nil
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

// LoadCompressedData loads and validates gzipped JSON data from a reader
func (server *Server) loadCompressedData(reader io.Reader) ([]byte, error) {
	server.logger.Enter("loadCompressedData")
	defer server.logger.Exit("loadCompressedData")

	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		server.logger.Failure("Failed to create gzip reader: %v", err)
		return nil, err
	}
	defer gzipReader.Close()

	return io.ReadAll(gzipReader)
}

func (server *Server) validateAndUnmarshal(data []byte, hash []byte, target interface{}) error {
	server.logger.Enter("validateAndUnmarshal")
	defer server.logger.Exit("validateAndUnmarshal")

	dataHash := sha256.New()
	dataHash.Write(data)
	if !compareHashes(hash, dataHash.Sum(nil)) {
		server.logger.Failure("Data hash mismatch, file may be corrupted")
		return fmt.Errorf("data hash mismatch, file may be corrupted")
	}

	if err := json.Unmarshal(data, target); err != nil {
		server.logger.Failure("Failed to unmarshal data: %v", err)
		return err
	}

	server.lastHash = hash
	// The unmarshalled value is NOT logged: it is the forest, and the forest carries password hashes.
	server.logger.Debug("Unmarshalled %d bytes of state", len(data))
	return nil
}
