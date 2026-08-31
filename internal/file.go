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
)

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
	server.logger.Debug("Loaded forest: %+v", server.forest)
	return nil
}

// TODO: Encrypt this
// Function to write changes to an encrypted state file
func (server *Server) writeChangesToFile(data interface{}, filename string) error {
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

	if dir := filepath.Dir(filename); dir != "" {
		_ = os.MkdirAll(dir, 0755)
	}

	tmpFile := filename + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		server.logger.Failure("Failed to create temporary file: %v", err)
		return err
	}
	defer file.Close()

	if _, err := file.Write(newHash); err != nil {
		os.Remove(tmpFile)
		server.logger.Failure("Failed to write hash to temporary file: %v", err)
		return err
	}

	gzipWriter := gzip.NewWriter(file)
	if _, err := gzipWriter.Write(jsonData); err != nil {
		os.Remove(tmpFile)
		server.logger.Failure("Failed to write compressed data to temporary file: %v", err)
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		os.Remove(tmpFile)
		server.logger.Failure("Failed to close gzip writer: %v", err)
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
	server.logger.Debug("Unmarshalled data: %+v", target)
	return nil
}
