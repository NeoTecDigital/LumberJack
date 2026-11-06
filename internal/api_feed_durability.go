// Written by Richard Christopher, Copyright 2026 Mindfull
package internal

import (
	"bytes"
	"crypto/sha256"
)

// Called with forest read/exclusive hold. Never writes or retries an ambiguous
// mutation. A hash comparison covers initialized markDurable and unchanged
// snapshot skips (stateSeq can advance without advancing durableSeq).
// Re-encoding also catches callback errors that changed memory without a seq.
func (s *Server) feedSnapshotDurable() bool {
	writer := s.stateWriter
	if writer == nil {
		return false
	}
	raw, err := encodeState(s.forest)
	if err != nil {
		return false
	}
	hash := sha256.Sum256(raw)
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	return writer.durableHash != nil && bytes.Equal(hash[:], writer.durableHash) && stateFileExists(s.statePath())
}
