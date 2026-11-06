// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestEnrollmentUnknownRetainedUntilActualPairedFileWitness(t *testing.T) {
	f := newEnrollmentFixture(t)
	actual := f.server.stateWriter.write
	f.server.stateWriter.write = func(snapshot stateSnapshot) error {
		if err := actual(snapshot); err != nil {
			return err
		}
		return errors.New("unit lost ACK after actual publication")
	}
	begin := f.enroll(t, f.input(EnrollmentProvision, "unit-unknown-account", "unit-unknown-command", "unit-unknown-proof", "absent", nil))
	received := f.received(t, begin)
	if received.Pair != nil || !f.server.sourceFence().unknown || f.server.forest.Children[begin.Lease.Binding.RootID] != nil {
		t.Fatal("unknown publication became successful native disclosure")
	}
	f.server.stateWriter.write = actual
	result := enrollmentDiscard(t, f, begin)
	if !result.Completed || f.server.sourceFence().unknown {
		t.Fatal("actual witnessed durable pair did not settle retained unknown")
	}
	root, _ := f.server.forest.GetNode(begin.Lease.Binding.RootID)
	if root == nil {
		t.Fatal("actual witnessed native root not published for cleanup")
	}
}

func TestEnrollmentUnknownDamagedOrCacheOnlyWitnessRemainsRetained(t *testing.T) {
	for _, damage := range []string{"cache-only", "missing", "tampered", "partial", "symlink"} {
		t.Run(damage, func(t *testing.T) { enrollmentDamagedWitness(t, damage) })
	}
}

func enrollmentDamagedWitness(t *testing.T, damage string) {
	t.Helper()
	f := newEnrollmentFixture(t)
	f.server.stateWriter.write = func(stateSnapshot) error { return errors.New("unit absent write ACK") }
	begin := f.enroll(t, f.input(EnrollmentProvision, "unit-damaged-account", "unit-damaged-command", "unit-damaged-proof", "absent", nil))
	f.received(t, begin)
	scope := f.server.stagedScopes[enrollmentScopeID("unit-damaged-account")]
	f.server.forestMutex.Lock()
	prepared, err := f.server.snapshotOwnedPreparationLocked(scope, scope.pending, scope.pending.key, true)
	f.server.forestMutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	enrollmentDamageWitness(t, f, prepared, damage)
	result := enrollmentDiscard(t, f, begin)
	if result.Completed || !f.server.sourceFence().unknown || scope.pending == nil {
		t.Fatal("absence/cache/damaged file became a real cleanup ACK")
	}
	if _, err = f.server.sourceFence().beginRead(nil); err == nil {
		t.Fatal("unresolved native writer produced current evidence")
	}
}

func enrollmentDamageWitness(t *testing.T, f *enrollmentFixture, prepared stagedPreparation, damage string) {
	t.Helper()
	path := f.server.statePath()
	switch damage {
	case "cache-only":
		writer := f.server.stateWriter
		writer.durableSeq, writer.durableHash, writer.durablePath, writer.durablePairs = prepared.snapshot.seq, prepared.snapshot.hash, path, prepared.snapshot.pairs
	case "missing":
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	case "tampered":
		if err := os.WriteFile(path, []byte("invalid unit snapshot"), 0600); err != nil {
			t.Fatal(err)
		}
	case "partial":
		enrollmentPartialWitness(t, f, prepared)
	case "symlink":
		enrollmentSymlinkWitness(t, path)
	}
}

func enrollmentPartialWitness(t *testing.T, f *enrollmentFixture, prepared stagedPreparation) {
	t.Helper()
	if err := f.server.publishSnapshot(prepared.snapshot); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.server.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.server.statePath(), raw[:len(raw)/2], 0600); err != nil {
		t.Fatal(err)
	}
}

func enrollmentSymlinkWitness(t *testing.T, path string) {
	t.Helper()
	if err := os.Rename(path, path+".unit-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".unit-old", path); err != nil {
		t.Fatal(err)
	}
}

func enrollmentDiscard(t *testing.T, f *enrollmentFixture, begin DomainBegin) DomainControlResult {
	t.Helper()
	control := DomainControl{Action: "finish", Epoch: begin.Lease.Epoch, LeaseID: begin.Lease.LeaseID, HostID: f.config.HostID, ChannelToken: f.config.ControlToken, ResponseHash: begin.ResponseHash, Disposition: "irrevocably-discarded"}
	result, err := f.server.DomainControl(context.Background(), control)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestEnrollmentActualRestartRestoresRegistryAndExactReplay(t *testing.T) {
	f := newEnrollmentFixture(t)
	first := f.enroll(t, f.input(EnrollmentProvision, "unit-restart-account", "unit-stable-create", "unit-before-restart", "absent", nil))
	restarted := stagedTestServer(t, f.server.config.Process.DatabasePath)
	if err := restarted.loadFromFile(f.server.statePath()); err != nil {
		t.Fatal(err)
	}
	policy, _ := NewDomainOwnerPolicy(f.config.ACLMetadataKey)
	if err := restarted.ConfigureDomain(f.config, map[string]DomainProduct{"manifest": domainTestProduct{}}, policy); err != nil {
		t.Fatal(err)
	}
	f.server = restarted
	f.mu.Lock()
	f.session = "unit-fresh-restart-session"
	f.mu.Unlock()
	replay := f.enroll(t, f.input(EnrollmentProvision, "unit-restart-account", "unit-stable-create", "unit-after-restart", "absent", nil))
	if replay.Lease.Binding != first.Lease.Binding || replay.Lease.Epoch == first.Lease.Epoch {
		t.Fatal("restart changed actual root or revived old lease epoch")
	}
	enrollmentAssertAppliedPair(t, f.received(t, replay), replay, "replayed")
}
