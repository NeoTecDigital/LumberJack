// Written by Richard Christopher, Copyright 2026 Richard Christopher

package internal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeoTecDigital/LumberJack/internal/graph"
	"github.com/NeoTecDigital/LumberJack/internal/persist"
	"github.com/NeoTecDigital/LumberJack/types"
)

// Tiered persistence: the hot log takes every commit, a cold writer rewrites the state file in
// the background, and recovery is the state file plus the log past it.
//
// WHAT A 200 PROMISES IS UNCHANGED. A commit is acknowledged once its record is as durable as
// hot_sync asks: on the disk for `commit`, written and syncing within the interval for `interval`,
// written for `none`. The forest lock covers the mutation and the ENCODING OF THE CHANGE, and the
// disk is outside it, exactly as the snapshot writer arranged.
//
// THE COLD WRITER HOLDS THE FOREST ONLY TO ENCODE IT. The hash, the gzip, the write and the
// fsyncs happen with the forest free, so a commit during a snapshot waits for one encode of the
// forest and not for the disk. The state file names the log sequence it contains; segments the
// file wholly covers are deleted after it is durable, never before.
type tier struct {
	config types.PersistenceConfig
	log    *persist.Log
	// cache holds each node as the state codec last encoded it, by id, for the whole-forest change
	// detection untracked callers fall back to. Nil marks a node the tracked path changed. It is
	// read and written under the exclusive forest hold only.
	cache map[string][]byte

	commits  atomic.Int64
	lastCold atomic.Uint64
	coldWake chan struct{}
	coldStop chan struct{}
	coldDone chan struct{}
	coldOnce sync.Once
	// snapshotting serializes cold snapshots, which the loop, persistState and the shutdown all ask
	// for.
	snapshotting sync.Mutex
}

// resolveStoreConfig fills the persistence and sync blocks a config left empty from the database
// directory's config.yaml, applies the defaults and validates the result.
func resolveStoreConfig(config *types.ServerConfig) error {
	if config.Persistence.Mode == "" && config.Sync.Role == "" {
		persistence, sync, err := types.LoadStoreConfig(config.Process.DatabasePath)
		if err != nil {
			return err
		}
		config.Persistence, config.Sync = persistence, sync
	}
	config.Persistence = config.Persistence.WithDefaults()
	config.Sync = config.Sync.WithDefaults()
	if err := config.Persistence.Validate(); err != nil {
		return err
	}
	return config.Sync.Validate()
}

// openStore brings persistence up over a table read from the state file, or over nothing for a
// fresh store, and installs the forest it recovers. In snapshot mode the forest is simply linked.
func (server *Server) openStore(table *stateTable) error {
	if err := resolveStoreConfig(&server.config); err != nil {
		return err
	}
	// The sync role is refused BEFORE the mode is looked at: a config that asks for a replica
	// must not come up as a lone snapshot store that believes it is replicating.
	hook, err := persist.OpenHook(server.config.Sync)
	if err != nil {
		return err
	}
	if server.config.Persistence.Mode != types.PersistenceTiered {
		return server.installTable(table)
	}
	if err := server.refuseTieredOnEncryptedStore(); err != nil {
		return err
	}
	if table == nil {
		table = &stateTable{Version: stateVersion, records: map[string]*nodeRecord{}, Nodes: map[string]json.RawMessage{}}
	}
	log, records, err := persist.Open(server.statePath(), server.config.Persistence, hook, table.LogSequence)
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := applyChangeBody(table, record.Seq, record.Body); err != nil {
			_ = log.Close()
			return err
		}
	}
	t := &tier{config: server.config.Persistence, log: log, cache: map[string][]byte{}}
	if len(table.records) > 0 {
		forest, err := linkTable(table)
		if err != nil {
			_ = log.Close()
			return err
		}
		server.forest = forest
		t.seedCache(table)
	}
	t.lastCold.Store(table.LogSequence)
	server.tier = t
	server.lastHash = sequenceToken(log.LastStaged())
	server.mutations.seed(log.LastStaged())
	t.startCold(server.snapshotCold, func(err error) { server.logger.Failure("Cold snapshot failed; the log holds every change: %v", err) })
	server.logger.Info("Tiered persistence: replayed %d log records past state sequence %d", len(records), table.LogSequence)
	return nil
}

// installTable links a loaded table into the server in snapshot mode. A nil table is a fresh
// forest, already in place.
func (server *Server) installTable(table *stateTable) error {
	if table == nil {
		return nil
	}
	forest, err := linkTable(table)
	if err != nil {
		return err
	}
	server.forest = forest
	return nil
}

// refuseTieredOnEncryptedStore keeps plaintext out of the log: an encrypted store seals the state
// file as a whole, and the log would hold every change in the clear beside it.
func (server *Server) refuseTieredOnEncryptedStore() error {
	storage, err := server.storageCodec()
	if err != nil {
		return err
	}
	if storage != nil {
		return fmt.Errorf("persistence.mode %q is not available on an encrypted store (CORRESPONDER_STORAGE_MODE=%s): "+
			"the hot log would hold the changes in plaintext beside the sealed state file; use %q",
			types.PersistenceTiered, os.Getenv("CORRESPONDER_STORAGE_MODE"), types.PersistenceSnapshot)
	}
	return nil
}

// seedCache fills the change cache from a table: the file's own bytes where the node came from
// the file untouched, a fresh encoding where the log changed it.
func (t *tier) seedCache(table *stateTable) {
	for id, record := range table.records {
		if raw, held := table.Nodes[id]; held {
			t.cache[id] = raw
			continue
		}
		encoded, err := encodeWholeNode(record.Node, record.Children)
		if err == nil {
			t.cache[id] = encoded
		}
	}
}

// sequenceToken is the read cache's invalidation token in tiered mode: it moves with every commit
// and is never the length of a sha256, so it cannot collide with a hash from a load.
func sequenceToken(seq uint64) []byte {
	token := make([]byte, 8)
	binary.LittleEndian.PutUint64(token, seq)
	return token
}

// persistBehind reports the forest ahead of its durable store, whichever mode holds it.
func (server *Server) persistBehind() bool {
	if server.tier != nil {
		return server.tier.log.Behind()
	}
	return server.stateWriter.behind()
}

// commitTiered is changeForest in tiered mode: the change and its encoding under the hold, the
// log outside it, and the acknowledgment once the record is durable.
func (server *Server) commitTiered(change func() (*graph.Touched, error), tracked bool) error {
	seq, err := server.stageChangeLocked(change, tracked)
	if err != nil {
		return err
	}
	if err := server.tier.log.Commit(seq); err != nil {
		server.logger.Failure("Failed to append to the log: %v", err)
		return apiErrorf(http.StatusInternalServerError, "Failed to save state")
	}
	if seq != 0 {
		server.tier.noteCommit()
	}
	return nil
}

// stageChangeLocked runs the change under the exclusive hold and stages its record. It answers
// the record's sequence, or zero when the change touched nothing.
func (server *Server) stageChangeLocked(change func() (*graph.Touched, error), tracked bool) (uint64, error) {
	server.forestMutex.Lock()
	defer server.forestMutex.Unlock()

	touched, err := server.runChangeLocked(change, tracked)
	if err != nil {
		return 0, err
	}
	var body []byte
	if touched != nil {
		body, err = server.tier.trackedChange(server.forest, touched)
	} else {
		body, err = server.tier.wholeForestChange(server.forest)
	}
	if err != nil {
		server.logger.Failure("Failed to encode the change: %v", err)
		return 0, apiErrorf(http.StatusInternalServerError, "Failed to save state")
	}
	if body == nil {
		return 0, nil
	}
	seq := server.tier.log.Stage(body)
	server.lastHash = sequenceToken(seq)
	return seq, nil
}

// noteCommit counts a commit toward the next cold snapshot and wakes the writer at the threshold.
func (t *tier) noteCommit() {
	if t.commits.Add(1) < int64(t.config.ColdEveryCommits) {
		return
	}
	t.commits.Store(0)
	select {
	case t.coldWake <- struct{}{}:
	default:
	}
}

// startCold runs the cold writer: a snapshot at every commit threshold, every cold_every_seconds
// when anything changed, and once more at close. A snapshot that fails is logged and the log
// keeps every change; the next threshold tries again.
func (t *tier) startCold(snapshot func() (uint64, error), report func(error)) {
	t.coldWake, t.coldStop, t.coldDone = make(chan struct{}, 1), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(t.coldDone)
		ticker := time.NewTicker(time.Duration(t.config.ColdEverySeconds) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-t.coldWake:
			case <-ticker.C:
			case <-t.coldStop:
				return
			}
			if _, err := snapshot(); err != nil {
				report(err)
			}
		}
	}()
}

// snapshotCold writes the state file for everything staged so far. The forest is held only for
// the encode. It answers the sequence the file now covers.
func (server *Server) snapshotCold() (uint64, error) {
	t := server.tier
	t.snapshotting.Lock()
	defer t.snapshotting.Unlock()

	server.forestMutex.Lock()
	seq := t.log.LastStaged()
	if seq == t.lastCold.Load() {
		server.forestMutex.Unlock()
		return seq, nil
	}
	data, err := encodeStateAt(server.forest, seq)
	t.log.RollAfter(seq)
	server.forestMutex.Unlock()
	if err != nil {
		return 0, err
	}

	hash := sha256.Sum256(data)
	if err := server.publishState(server.statePath(), hash[:], data); err != nil {
		return 0, err
	}
	t.lastCold.Store(seq)
	if err := t.log.Trim(seq); err != nil {
		server.logger.Warn("Could not trim the log after the snapshot at %d: %v", seq, err)
	}
	return seq, nil
}

// closeStore takes the clean-shutdown snapshot and closes the log. Shutdown calls it last, with
// nothing serving.
func (server *Server) closeStore() error {
	t := server.tier
	if t == nil {
		return nil
	}
	t.stopCold()
	var err error
	if _, snapErr := server.snapshotCold(); snapErr != nil {
		server.logger.Failure("Shutdown snapshot failed; the log holds every change: %v", snapErr)
		err = snapErr
	}
	if closeErr := t.log.Close(); err == nil {
		err = closeErr
	}
	return err
}

// stopCold ends the cold writer and waits for it.
func (t *tier) stopCold() {
	t.coldOnce.Do(func() {
		close(t.coldStop)
		<-t.coldDone
	})
}
