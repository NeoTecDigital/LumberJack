// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"
)

func TestPersonalSourceUnknownActualFileWitnessNotCache(t *testing.T) {
	f := sourceUnitFixtureNew(t)
	e, raw, a := sourceUnitAdmitted(t, f)
	actual := f.server.stateWriter.write
	f.server.stateWriter.write = func(snapshot stateSnapshot) error {
		if err := actual(snapshot); err != nil {
			return err
		}
		return errors.New("unit unknown after actual publish")
	}
	_, err := f.p.executePersonal(context.Background(), sourceUnitRequest(f, "binding.provision", sourcePersonalExecute{raw, a.ExecutionLease, "unit_unknown_proof"}))
	if err == nil || e.state != "unknown" || f.server.forest.Children[e.candidate.RootID] != nil {
		t.Fatal("unknown became successful")
	}
	if f.server.stateWriter.durablePairs != nil {
		t.Fatal("test cache not invalidated")
	}
	f.server.stateWriter.write = actual
	if err = f.p.recoverPersonalWitness(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if e.state != "committed" || f.server.forest.Children[e.candidate.RootID] == nil {
		t.Fatal("actual witness not recovered")
	}
}
func TestPersonalSourceUnknownTamperedMissingAndSymlinkStayRetained(t *testing.T) {
	for _, damage := range []string{"missing", "cache-only", "tampered", "partial", "stale", "symlink"} {
		t.Run(damage, func(t *testing.T) { sourceUnitDamagedWitness(t, damage) })
	}
}
func sourceUnitDamagedWitness(t *testing.T, damage string) {
	f := sourceUnitFixtureNew(t)
	e, raw, a := sourceUnitAdmitted(t, f)
	f.server.stateWriter.write = func(stateSnapshot) error { return errors.New("unit absent acknowledgment") }
	_, _ = f.p.executePersonal(context.Background(), sourceUnitRequest(f, "binding.provision", sourcePersonalExecute{raw, a.ExecutionLease, "unit_unknown_proof"}))
	path := f.server.statePath()
	if damage == "cache-only" {
		writer := f.server.stateWriter
		writer.durableSeq, writer.durableHash, writer.durablePath, writer.durablePairs = e.snapshot.seq, e.snapshot.hash, path, e.snapshot.pairs
	}
	if damage == "tampered" {
		_ = os.WriteFile(path, []byte("invalid unit data"), 0600)
	}
	if damage == "partial" {
		_ = f.server.publishSnapshot(e.snapshot)
		stored, _ := os.ReadFile(path)
		_ = os.WriteFile(path, stored[:len(stored)/2], 0600)
	}
	if damage == "stale" {
		old := e.snapshot
		old.data, _ = encodeState(f.server.forest)
		hash := sha256.Sum256(old.data)
		old.hash = hash[:]
		_ = f.server.publishSnapshot(old)
	}
	if damage == "symlink" {
		other := path + ".other"
		_ = os.WriteFile(other, []byte("not a pair"), 0600)
		_ = os.Symlink(other, path)
	}
	if f.p.recoverPersonalWitness(context.Background(), e) == nil || e.state != "unknown" || e.source.closed {
		t.Fatal("unwitnessed cleanup/recovery")
	}
	if _, err := f.p.coordinator.beginRead(nil); err == nil {
		t.Fatal("unknown produced evidence")
	}
}
func TestPersonalSourceWriterWaitAndZeroRootSessionFence(t *testing.T) {
	f := sourceUnitFixtureNew(t)
	read, err := f.p.coordinator.beginRead(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err = f.p.coordinator.beginWrite(ctx, "unit-write"); err == nil {
		t.Fatal("write bypassed live source reader")
	}
	read.release()
	if err = f.p.coordinator.fenceSession(enrollmentSessionKey{f.actor.PrincipalID, f.actor.SessionID}, 32); err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.coordinator.reserveSession(enrollmentSessionKey{f.actor.PrincipalID, f.actor.SessionID}, 32); err == nil {
		t.Fatal("zero-root fence bypassed")
	}
}
