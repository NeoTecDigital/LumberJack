// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
)

func TestStagedFailedPersistRetainsUnknownAndSameEnvelopeReconciles(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "retry")
	publish := server.stateWriter.write
	server.stateWriter.write = func(stateSnapshot) error { return errors.New("synthetic disk failure") }
	result, err := server.stageOwnedCommand(command, stagedTestAllow, stagedTestLabel("pending value"))
	if err == nil || result.Status != "unknown" || result.Durable != nil {
		t.Fatalf("failed persistence = %#v, %v", result, err)
	}
	failedSequence := server.stateWriter.failedSeq
	stagedTestRequireLabel(t, stagedTestRecord(t, server.forest), "original")
	if _, err := server.readOwnedScope("owned-scope", stagedTestAllow); !errors.Is(err, errStagedPending) {
		t.Fatalf("unconfirmed namespace was disclosed: %v", err)
	}
	server.stateWriter.write = publish
	neverBuild := func(stagedView) (stagedDelta, error) {
		t.Fatal("retry applied the setter a second time")
		return stagedDelta{}, nil
	}
	result, err = server.stageOwnedCommand(command, stagedTestAllow, neverBuild)
	if err != nil || result.Status != "replayed" || result.Durable.Sequence <= failedSequence {
		t.Fatalf("same-envelope reconciliation = %#v, %v", result, err)
	}
	stagedTestRequireLabel(t, stagedTestRecord(t, stagedTestDisk(t, server)), "pending value")
}

func TestStagedLostAcknowledgmentDoesNotClaimRollback(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "lost-ack")
	publish := server.stateWriter.write
	server.stateWriter.write = func(snapshot stateSnapshot) error {
		if err := publish(snapshot); err != nil {
			return err
		}
		return errors.New("synthetic acknowledgment loss after actual publish")
	}
	result, err := server.stageOwnedCommand(command, stagedTestAllow, stagedTestLabel("already on disk"))
	if err == nil || result.Status != "unknown" {
		t.Fatalf("lost acknowledgment = %#v, %v", result, err)
	}
	stagedTestRequireLabel(t, stagedTestRecord(t, server.forest), "original")
	stagedTestRequireLabel(t, stagedTestRecord(t, stagedTestDisk(t, server)), "already on disk")
	server.stateWriter.write = publish
	result, err = server.reconcileOwnedCommand(command.ScopeID, stagedCommandKey(command))
	if err != nil || result.Durable == nil {
		t.Fatalf("actual paired reconciliation = %#v, %v", result, err)
	}
	stagedTestRequireLabel(t, stagedTestRecord(t, server.forest), "already on disk")
}

func TestStagedCoalescingIncludesPairAndDoesNotHoldForestDuringIO(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "coalesced")
	publish := server.stateWriter.write
	started, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	server.stateWriter.write = func(snapshot stateSnapshot) error {
		first.Do(func() { close(started); <-release })
		return publish(snapshot)
	}
	stagedDone := make(chan struct{})
	var stagedErr error
	go func() {
		_, stagedErr = server.stageOwnedCommand(command, stagedTestAllow, stagedTestLabel("paired"))
		close(stagedDone)
	}()
	stagedTestAwait(t, started)
	readDone := make(chan struct{})
	go func() { server.readForest(func() {}); close(readDone) }()
	stagedTestAwait(t, readDone)
	stagedTestRequireLabel(t, stagedTestRecord(t, server.forest), "original")
	legacyDone := make(chan struct{})
	var legacyErr error
	go func() {
		legacyErr = server.changeForest(func() error {
			server.forest.Metadata = map[string]interface{}{"unrelated": "retained"}
			return nil
		})
		close(legacyDone)
	}()
	stagedTestWaitPending(t, server.stateWriter)
	close(release)
	stagedTestAwait(t, stagedDone)
	stagedTestAwait(t, legacyDone)
	if stagedErr != nil || legacyErr != nil {
		t.Fatalf("staged/legacy commit failed: %v / %v", stagedErr, legacyErr)
	}
	stored := stagedTestDisk(t, server)
	if stored.Metadata["unrelated"] != "retained" {
		t.Fatal("selected publication replaced unrelated concurrent legacy changes")
	}
	stagedTestRequireLabel(t, stagedTestRecord(t, stored), "paired")
}

func TestStagedSequenceAloneCannotAcknowledgeDiscardedPair(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "missing-pair")
	prepared, err := server.prepareOwnedCommand(command, stagedTestAllow, stagedTestLabel("must not be acknowledged"))
	if err != nil {
		t.Fatal(err)
	}
	server.forestMutex.Lock()
	data, err := encodeState(server.forest)
	server.stateSeq++
	hash := sha256.Sum256(data)
	newer := stateSnapshot{seq: server.stateSeq, data: data, path: server.statePath(), hash: hash[:]}
	server.forestMutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately violate the encoder contract to test the independent acknowledgment gate.
	if err := server.stateWriter.commit(newer); err != nil {
		t.Fatal(err)
	}
	if stamp, err := server.stateWriter.commitPaired(prepared.snapshot, prepared.pair); err == nil || stamp.Sequence != 0 {
		t.Fatalf("durableSeq faked a receipt: %#v, %v", stamp, err)
	}
	stagedTestRequireLabel(t, stagedTestRecord(t, server.forest), "original")
}

func TestStagedDeniedRetryDoesNotRelabelUnknownAsRefused(t *testing.T) {
	server := stagedTestConfigured(t)
	command := stagedTestCommand(t, server, "revoked-retry")
	server.stateWriter.write = func(stateSnapshot) error { return errors.New("synthetic disk failure") }
	if result, err := server.stageOwnedCommand(command, stagedTestAllow, stagedTestLabel("pending")); err == nil || result.Status != "unknown" {
		t.Fatalf("initial unknown = %#v, %v", result, err)
	}
	deny := func(stagedAccess) error { return errors.New("synthetic current authority revoked") }
	result, err := server.stageOwnedCommand(command, deny, stagedTestLabel("pending"))
	if err == nil || result.Status != "unknown" || result.Durable != nil || server.stagedScopes[command.ScopeID].pending == nil {
		t.Fatalf("revoked retry lost truthful unknown: %#v, %v", result, err)
	}
}
