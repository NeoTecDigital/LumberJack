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

	// Read hash first
	hash := make([]byte, sha256.Size)
	if _, err := file.Read(hash); err != nil {
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

	// Important: Copy the loaded forest to server's forest
	server.forest = &loadedForest
	// The forest is NOT logged. It carries its users, and its users carry bcrypt hashes; Debug is
	// ungated and the log file it writes to is the one GET /logs serves.
	server.logger.Debug("Loaded forest with %d users and %d children", len(server.forest.Users), len(server.forest.Children))
	return nil
}

// TODO: Encrypt this
// writeChangesToFile persists the WHOLE forest to the state file. It took a `data interface{}`
// that it never looked at — callers passed a node or the forest and got the forest either way.
func (server *Server) writeChangesToFile(filename string) error {
	server.logger.Enter("writeChangesToFile")
	defer server.logger.Exit("writeChangesToFile")

	server.mutex.Lock()
	defer server.mutex.Unlock()

	// Always save the entire forest state
	jsonData, err := json.Marshal(server.forest)
	if err != nil {
		server.logger.Failure("Failed to marshal forest: %v", err)
		return err
	}

	hash := sha256.New()
	hash.Write(jsonData)
	newHash := hash.Sum(nil)

	if server.lastHash != nil && compareHashes(server.lastHash, newHash) {
		server.logger.Debug("No changes to save")
		return nil
	}

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

	server.lastHash = newHash
	server.logger.Debug("Saved changes to file: %s", filename)
	return nil
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
