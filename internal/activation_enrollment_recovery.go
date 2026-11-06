// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"encoding/hex"
	"path/filepath"
)

// Reconciliation reads/fsyncs exact already-written bytes. It never writes an
// expired owner's candidate, or treats writer cache/file existence as an ACK.
func (s *Server) inspectEnrollmentPair(ctx context.Context, snapshot stateSnapshot, pair stagedPair, maximum int) (*sourceStorageWitness, error) {
	if snapshot.path != s.statePath() || snapshot.seq == 0 || maximum <= 0 {
		return nil, sourceUnavailable()
	}
	writer := s.stateWriter
	writer.mutex.Lock()
	defer writer.mutex.Unlock()
	if writer.flushing || ctx.Err() != nil {
		return nil, sourceUnavailable()
	}
	file, dir, err := sourceWitnessFiles(snapshot.path)
	if err != nil {
		return nil, err
	}
	witness := &sourceStorageWitness{file: file, dir: dir, path: snapshot.path}
	dataPairs, err := s.validateEnrollmentWitness(ctx, witness, snapshot, pair, maximum)
	if err != nil {
		witness.close()
		return nil, sourceUnavailable()
	}
	writer.durableSeq, writer.durableHash, writer.durablePath, writer.durablePairs = snapshot.seq, append([]byte(nil), snapshot.hash...), snapshot.path, dataPairs
	witness.stamp, err = writer.pairedStamp(snapshot.path, &pair)
	if err != nil {
		witness.close()
		return nil, err
	}
	return witness, nil
}

func (s *Server) validateEnrollmentWitness(ctx context.Context, witness *sourceStorageWitness, snapshot stateSnapshot, pair stagedPair, maximum int) (map[string]stagedPair, error) {
	data, err := s.sourceWitnessPayload(witness.file, maximum)
	if err != nil || ctx.Err() != nil || stagedHash(data) != hex.EncodeToString(snapshot.hash) {
		return nil, sourceUnavailable()
	}
	pairs, err := stagedPairsFromBytes(data)
	if err != nil || !matchingStagedPair(pairs, pair) || !equalStagedPairs(snapshot.pairs, pairs) {
		return nil, sourceUnavailable()
	}
	if !sourceFileIdentity(witness.file, snapshot.path) || !sourceFileIdentity(witness.dir, filepath.Dir(snapshot.path)) || witness.file.Sync() != nil || witness.dir.Sync() != nil || ctx.Err() != nil || !witness.current() {
		return nil, sourceUnavailable()
	}
	return pairs, nil
}
